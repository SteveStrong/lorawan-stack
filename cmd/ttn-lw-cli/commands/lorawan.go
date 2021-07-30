// Copyright © 2021 The Things Network Foundation, The Things Industries B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"bytes"
	"fmt"
	"os"

	"github.com/mohae/deepcopy"
	"github.com/spf13/cobra"
	"go.thethings.network/lorawan-stack/v3/cmd/internal/io"
	"go.thethings.network/lorawan-stack/v3/pkg/band"
	"go.thethings.network/lorawan-stack/v3/pkg/crypto"
	"go.thethings.network/lorawan-stack/v3/pkg/encoding/lorawan"
	"go.thethings.network/lorawan-stack/v3/pkg/log"
	"go.thethings.network/lorawan-stack/v3/pkg/ttnpb"
	"go.thethings.network/lorawan-stack/v3/pkg/types"
)

type lorawanDecodedFrame struct {
	MHDR *ttnpb.MHDR `json:"mhdr,omitempty"`
	MIC  []byte      `json:"mic,omitempty"`

	MACCommands []*ttnpb.MACCommand `json:"mac_commands,omitempty"`
	MACPayload  *ttnpb.MACPayload   `json:"mac_payload,omitempty"`

	JoinAcceptPayload    *ttnpb.JoinAcceptPayload    `json:"join_accept_payload,omitempty"`
	JoinRequestPayload   *ttnpb.JoinRequestPayload   `json:"join_request_payload,omitempty"`
	RejoinRequestPayload *ttnpb.RejoinRequestPayload `json:"rejoin_request_payload,omitempty"`
}

type lorawanConfig struct {
	Band       band.Band
	MACVersion ttnpb.MACVersion
	PHYVersion ttnpb.PHYVersion

	AppKey  types.AES128Key
	AppSKey types.AES128Key
	NwkSKey types.AES128Key
}

func getMacBuffer(p *ttnpb.MACPayload) []byte {
	if p.FPort == 0 && len(p.FRMPayload) > 0 {
		return p.FRMPayload
	}
	return p.FOpts
}
func setMacBuffer(p *ttnpb.MACPayload, buf []byte) {
	if p.FPort == 0 && len(p.FRMPayload) > 0 {
		p.FRMPayload = buf
	} else {
		p.FOpts = buf
	}
}

func decodeJoinRequest(msg ttnpb.Message, config lorawanConfig) (*lorawanDecodedFrame, error) {
	pld := msg.GetJoinRequestPayload()
	return &lorawanDecodedFrame{
		MHDR:               &msg.MHDR,
		MIC:                msg.MIC,
		JoinRequestPayload: pld,
	}, nil
}

func decodeUplink(msg ttnpb.Message, config lorawanConfig) (*lorawanDecodedFrame, error) {

	pld := msg.GetMACPayload()
	macBuf := getMacBuffer(pld)
	if len(macBuf) > 0 && (len(pld.FOpts) == 0 || config.MACVersion.EncryptFOpts()) && !config.NwkSKey.IsZero() {
		logger.Debug("Decrypting MAC buffer")
		for msb := uint32(0); msb < 0xff; msb++ {
			fCnt := msb<<8 | pld.FCnt
			macBuf, err := crypto.DecryptUplink(config.NwkSKey, pld.DevAddr, fCnt, macBuf, pld.FPort != 0)
			if err == nil {
				setMacBuffer(pld, macBuf)
				break
			}
			logger.WithField("f_cnt", fCnt).Debug("Failed attempt to decrypt MAC buffer")
		}
	}
	var macCommands []*ttnpb.MACCommand
	for r := bytes.NewReader(macBuf); r.Len() > 0; {
		cmd := &ttnpb.MACCommand{}
		if err := lorawan.DefaultMACCommands.ReadUplink(config.Band, r, cmd); err != nil {
			logger.WithError(err).Warn("Failed to read MAC command")
		} else {
			macCommands = append(macCommands, cmd)
		}
	}
	if pld.FPort > 0 {
		if config.AppSKey.IsZero() {
			logger.Debug("No AppSKey provided, skipping application payload decryption")
		} else {
			logger.Debug("Decrypting application payload")
			buf, err := crypto.DecryptUplink(config.AppSKey, pld.DevAddr, pld.FCnt, pld.FRMPayload, false)
			if err != nil {
				logger.WithField("f_cnt", pld.FCnt).Debug("Failed attempt to decrypt FRMPayload")
			} else {
				pld.FRMPayload = buf
			}
		}
	}
	return &lorawanDecodedFrame{
		MHDR:        &msg.MHDR,
		MIC:         msg.MIC,
		MACCommands: macCommands,
		MACPayload:  pld,
	}, nil
}

func decodeJoinAccept(msg ttnpb.Message, config lorawanConfig) (*lorawanDecodedFrame, error) {
	pld := msg.GetJoinAcceptPayload()
	f := &lorawanDecodedFrame{
		MHDR:              &msg.MHDR,
		MIC:               msg.MIC,
		JoinAcceptPayload: pld,
	}
	if config.AppKey.IsZero() {
		logger.Debug("No AppKey provided, skipping join accept decryption")
	} else {
		buf, err := crypto.DecryptJoinAccept(config.AppKey, pld.Encrypted)
		if err != nil {
			return nil, err
		}
		n := len(buf)
		if n < 4 {
			logger.WithFields(log.Fields("length", n, "minimum", 4)).Warn("Invalid Join Accept message length")
			return f, nil
		}
		buf, mic := buf[:n-4], buf[n-4:]
		decBuf := deepcopy.Copy(pld).(*ttnpb.JoinAcceptPayload)
		if err := lorawan.UnmarshalJoinAcceptPayload(buf, decBuf); err != nil {
			logger.WithError(err).Warn("Failed to unmarshal join accept payload")
			return f, nil
		}

		f.MIC = mic
		f.JoinAcceptPayload = decBuf
	}
	return f, nil
}

func decodeDownlink(msg ttnpb.Message, config lorawanConfig) (*lorawanDecodedFrame, error) {
	pld := msg.GetMACPayload()

	macBuf := getMacBuffer(pld)
	if len(macBuf) > 0 && (len(pld.FOpts) == 0 || config.MACVersion.EncryptFOpts()) && !config.NwkSKey.IsZero() {
		logger.Debug("Decrypting MAC buffer")
		for msb := uint32(0); msb < 0xff; msb++ {
			fCnt := msb<<8 | pld.FCnt
			macBuf, err := crypto.DecryptDownlink(config.NwkSKey, pld.DevAddr, fCnt, macBuf, pld.FPort != 0)
			if err == nil {
				setMacBuffer(pld, macBuf)
				break
			}
			logger.WithField("f_cnt", fCnt).Debug("Failed attempt to decrypt MAC buffer")
		}
	}
	var macCommands []*ttnpb.MACCommand
	for r := bytes.NewReader(macBuf); r.Len() > 0; {
		cmd := &ttnpb.MACCommand{}
		if err := lorawan.DefaultMACCommands.ReadDownlink(config.Band, r, cmd); err != nil {
			logger.WithError(err).Warn("Failed to read MAC command")
		} else {
			macCommands = append(macCommands, cmd)
		}
	}
	if pld.FPort > 0 {
		if config.AppSKey.IsZero() {
			logger.Debug("No AppSKey provided, skipping application payload decryption")
		} else {
			logger.Debug("Decrypting application payload")
			buf, err := crypto.DecryptDownlink(config.AppSKey, pld.DevAddr, pld.FCnt, pld.FRMPayload, false)
			if err != nil {
				logger.WithField("f_cnt", pld.FCnt).Debug("Failed attempt to decrypt FRMPayload")
			} else {
				pld.FRMPayload = buf
			}
		}
	}

	return &lorawanDecodedFrame{
		MHDR:        &msg.MHDR,
		MIC:         msg.MIC,
		MACPayload:  pld,
		MACCommands: macCommands,
	}, nil
}

func decodeFrame(msg ttnpb.Message, config lorawanConfig) (*lorawanDecodedFrame, error) {
	switch msg.MHDR.MType {
	case ttnpb.MType_JOIN_REQUEST:
		return decodeJoinRequest(msg, config)
	case ttnpb.MType_CONFIRMED_UP, ttnpb.MType_UNCONFIRMED_UP:
		return decodeUplink(msg, config)
	case ttnpb.MType_JOIN_ACCEPT:
		return decodeJoinAccept(msg, config)
	case ttnpb.MType_CONFIRMED_DOWN, ttnpb.MType_UNCONFIRMED_DOWN:
		return decodeDownlink(msg, config)
	}

	return nil, fmt.Errorf("not implemented")
}

var (
	lorawanCmd = &cobra.Command{
		Use:     "lorawan",
		Aliases: []string{"lw"},
		Short:   "LoRaWAN commands",
	}
	lorawanDecodeCmd = &cobra.Command{
		Use:     "decode",
		Aliases: []string{"d"},
		Short:   "Decode LoRaWAN frames",
		Example: `
	echo 'QL8AACeFAQADBwb/CP6z6aY=' | ttn-lw-cli lorawan decode --input-format base64
		`,
		RunE: asBulk(func(cmd *cobra.Command, args []string) error {
			switch config.InputFormat {
			case "hex", "base64":
			default:
				return fmt.Errorf("command supports only hex and base64 input formats")
			}
			lorawanConfig := lorawanConfig{}
			lorawanVersionStr, _ := cmd.Flags().GetString("lorawan-version")
			if err := lorawanConfig.MACVersion.UnmarshalText([]byte(lorawanVersionStr)); err != nil {
				return err
			}
			lorawanPhyVersionStr, _ := cmd.Flags().GetString("lorawan-phy-version")
			if err := lorawanConfig.PHYVersion.UnmarshalText([]byte(lorawanPhyVersionStr)); err != nil {
				return err
			}
			appKeyStr, _ := cmd.Flags().GetString("app-key")
			if err := lorawanConfig.AppKey.UnmarshalText([]byte(appKeyStr)); err != nil {
				return err
			}
			appSKeyStr, _ := cmd.Flags().GetString("app-s-key")
			if err := lorawanConfig.AppSKey.UnmarshalText([]byte(appSKeyStr)); err != nil {
				return err
			}
			nwkSKeyStr, _ := cmd.Flags().GetString("nwk-s-key")
			if err := lorawanConfig.NwkSKey.UnmarshalText([]byte(nwkSKeyStr)); err != nil {
				return err
			}
			bandID, _ := cmd.Flags().GetString("band")
			if bandID != "" {
				band, err := band.GetByID(bandID)
				if err != nil {
					return err
				}
				lorawanConfig.Band = band
			}

			if inputDecoder == nil {
				return nil
			}
			var input []byte
			if _, err := inputDecoder.Decode(&input); err != nil {
				return err
			}
			var frame ttnpb.Message
			if err := lorawan.UnmarshalMessage(input, &frame); err != nil {
				return fmt.Errorf("failed to decode LoRaWAN frame: %w", err)
			}

			decoded, err := decodeFrame(frame, lorawanConfig)
			if err != nil {
				return err
			}
			return io.Write(os.Stdout, config.OutputFormat, decoded)
		}),
	}
)

func init() {
	lorawanDecodeCmd.Flags().String("lorawan-version", "1.0.2", "LoRaWAN version")
	lorawanDecodeCmd.Flags().String("lorawan-phy-version", "1.0.2-b", "LoRaWAN Regional Parameters version")
	lorawanDecodeCmd.Flags().String("band", "EU_863_870", "LoRaWAN Band ID")
	lorawanDecodeCmd.Flags().String("app-key", "", "LoRaWAN AppKey")
	lorawanDecodeCmd.Flags().String("app-s-key", "", "LoRaWAN AppSKey")
	lorawanDecodeCmd.Flags().String("nwk-s-key", "", "LoRaWAN NwkSKey")

	lorawanCmd.AddCommand(lorawanDecodeCmd)

	Root.AddCommand(lorawanCmd)
}
