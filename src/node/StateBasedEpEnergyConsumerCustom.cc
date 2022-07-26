//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

/*
#include "inet/common/ModuleAccess.h"
#include "StateBasedEpEnergyConsumerCustom.h"


Define_Module(StateBasedEpEnergyConsumerCustom);

void StateBasedEpEnergyConsumerCustom::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        offPowerConsumption = inet::W(par("offPowerConsumption"));
        sleepPowerConsumption = inet::W(par("sleepPowerConsumption"));
        switchingPowerConsumption = inet::W(par("switchingPowerConsumption"));
        receiverIdlePowerConsumption = inet::W(par("receiverIdlePowerConsumption"));
        receiverBusyPowerConsumption = inet::W(par("receiverBusyPowerConsumption"));
        receiverReceivingPowerConsumption = inet::W(par("receiverReceivingPowerConsumption"));
        receiverReceivingPreamblePowerConsumption = inet::W(par("receiverReceivingPreamblePowerConsumption"));
        receiverReceivingHeaderPowerConsumption = inet::W(par("receiverReceivingHeaderPowerConsumption"));
        receiverReceivingDataPowerConsumption = inet::W(par("receiverReceivingDataPowerConsumption"));
        transmitterIdlePowerConsumption = inet::W(par("transmitterIdlePowerConsumption"));
        transmitterTransmittingPowerConsumption = inet::W(par("transmitterTransmittingPowerConsumption"));
        transmitterTransmittingPreamblePowerConsumption = inet::W(par("transmitterTransmittingPreamblePowerConsumption"));
        transmitterTransmittingHeaderPowerConsumption = inet::W(par("transmitterTransmittingHeaderPowerConsumption"));
        transmitterTransmittingDataPowerConsumption = inet::W(par("transmitterTransmittingDataPowerConsumption"));
        cModule *radioModule = getParentModule();
        radioModule->subscribe(inet::physicallayer::IRadio::radioModeChangedSignal, this);
        radioModule->subscribe(inet::physicallayer::IRadio::receptionStateChangedSignal, this);
        radioModule->subscribe(inet::physicallayer::IRadio::transmissionStateChangedSignal, this);
        radioModule->subscribe(inet::physicallayer::IRadio::receivedSignalPartChangedSignal, this);
        radioModule->subscribe(inet::physicallayer::IRadio::transmittedSignalPartChangedSignal, this);
        radio = check_and_cast<inet::physicallayer::IRadio *>(radioModule);
        powerConsumption = inet::W(0);
        packetSize = 0;
        energySource = inet::getModuleFromPar<inet::power::IEpEnergySource>(par("energySourceModule"), this);
        WATCH(powerConsumption);
    }
    else if (stage == inet::INITSTAGE_POWER)
        energySource->addEnergyConsumer(this);
}


inet::W StateBasedEpEnergyConsumerCustom::computePowerConsumption() const
{
    inet::physicallayer::IRadio::RadioMode radioMode = radio->getRadioMode();
    if (radioMode == inet::physicallayer::IRadio::RADIO_MODE_OFF)
        return offPowerConsumption;
    else if (radioMode == inet::physicallayer::IRadio::RADIO_MODE_SLEEP)
        return sleepPowerConsumption;
    else if (radioMode == inet::physicallayer::IRadio::RADIO_MODE_SWITCHING)
        return switchingPowerConsumption;
    inet::W powerConsumption = inet::W(0);
    inet::physicallayer::IRadio::ReceptionState receptionState = radio->getReceptionState();
    inet::physicallayer::IRadio::TransmissionState transmissionState = radio->getTransmissionState();
    if (radioMode == inet::physicallayer::IRadio::RADIO_MODE_RECEIVER || radioMode == inet::physicallayer::IRadio::RADIO_MODE_TRANSCEIVER) {
        switch (receptionState) {
        case inet::physicallayer::IRadio::RECEPTION_STATE_IDLE:
            powerConsumption += receiverIdlePowerConsumption;
            break;
        case inet::physicallayer::IRadio::RECEPTION_STATE_BUSY:
            powerConsumption += receiverBusyPowerConsumption;
            break;
        case inet::physicallayer::IRadio::RECEPTION_STATE_RECEIVING: {
            auto part = radio->getReceivedSignalPart();
            switch (part) {
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_NONE:
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_WHOLE:
                powerConsumption += receiverReceivingPowerConsumption;

                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_PREAMBLE:
                powerConsumption += receiverReceivingPreamblePowerConsumption;
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_HEADER:
                powerConsumption += receiverReceivingHeaderPowerConsumption;
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_DATA:
                powerConsumption += receiverReceivingDataPowerConsumption;
                break;
            default:
                throw inet::cRuntimeError("Unknown received signal part");
            }
            break;
        }
        case inet::physicallayer::IRadio::RECEPTION_STATE_UNDEFINED:
            break;
        default:
            throw inet::cRuntimeError("Unknown radio reception state");
        }
    }
    if (radioMode == inet::physicallayer::IRadio::RADIO_MODE_TRANSMITTER || radioMode == inet::physicallayer::IRadio::RADIO_MODE_TRANSCEIVER) {
        switch (transmissionState) {
        case inet::physicallayer::IRadio::TRANSMISSION_STATE_IDLE:
            powerConsumption += transmitterIdlePowerConsumption;
            break;
        case inet::physicallayer::IRadio::TRANSMISSION_STATE_TRANSMITTING: {
            auto part = radio->getTransmittedSignalPart();
            switch (part) {
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_NONE:
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_WHOLE:
                powerConsumption += transmitterTransmittingPowerConsumption;
                std::cout << powerConsumption << inet::endl;
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_PREAMBLE:
                powerConsumption += transmitterTransmittingPreamblePowerConsumption;
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_HEADER:
                powerConsumption += transmitterTransmittingHeaderPowerConsumption;
                break;
            case inet::physicallayer::IRadioSignal::SIGNAL_PART_DATA:
                powerConsumption += transmitterTransmittingDataPowerConsumption;
                break;
            default:
                throw inet::cRuntimeError("Unknown transmitted signal part");
            }
            break;
        }
        case inet::physicallayer::IRadio::TRANSMISSION_STATE_UNDEFINED:
            break;
        default:
            throw inet::cRuntimeError("Unknown radio transmission state");
        }
    }
    return powerConsumption;
}
*/

