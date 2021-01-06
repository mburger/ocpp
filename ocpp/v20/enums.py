from enum import Enum


class Action(str, Enum):
    """ An Action is a required part of a Call message. """
    Authorize = "Authorize"
    BootNotification = "BootNotification"
    CancelReservation = "CancelReservation"
    CertificateSigned = "CertificateSigned"
    ChangeAvailability = "ChangeAvailability"
    ClearCache = "ClearCache"
    ClearChargingProfile = "ClearChargingProfile"
    ClearDisplayMessage = "ClearDisplayMessage"
    ClearedChargingLimit = "ClearedChargingLimit"
    ClearVariableMonitoring = "ClearVariableMonitoring"
    CostUpdate = "CostUpdate"
    CustomerInformation = "CustomerInformation"
    DataTransfer = "DataTransfer"
    DeleteCertificate = "DeleteCertificate"
    FirmwareStatusNotification = "FirmwareStatusNotification"
    Get15118EVCertificate = "Get15118EVCertificate"
    GetBaseReport = "GetBaseReport"
    GetCertificateStatus = "GetCertificateStatus"
    GetChargingProfiles = "GetChargingProfiles"
    GetCompositeSchedule = "GetCompositeSchedule"
    GetDisplayMessages = "GetDisplayMessages"
    GetInstalledCertificateIds = "GetInstalledCertificateIds"
    GetLocalListVersion = "GetLocalListVersion"
    GetLog = "GetLog"
    GetMonitoringReport = "GetMonitoringReport"
    GetReport = "GetReport"
    GetTransactionStatus = "GetTransactionStatus"
    GetVariables = "GetVariables"
    Heartbeat = "Heartbeat"
    InstallCertificate = "InstallCertificate"
    LogStatusNotification = "LogStatusNotification"
    MeterValues = "MeterValues"
    NotifyChargingLimit = "NotifyChargingLimit"
    NotifyCustomerInformation = "NotifyCustomerInformation"
    NotifyDisplayMessages = "NotifyDisplayMessages"
    NotifyEVChargingNeeds = "NotifyEVChargingNeeds"
    NotifyEVChargingSchedule = "NotifyEVChargingSchedule"
    NotifyEvent = "NotifyEvent"
    NotifyMonitoringReport = "NotifyMonitoringReport"
    NotifyReport = "NotifyReport"
    PublishFirmware = "PublishFirmware"
    PublishFirmwareStatusNotification = "PublishFirmwareStatusNotification"
    ReportChargingProfiles = "ReportChargingProfiles"
    RequestStartTransaction = "RequestStartTransaction"
    RequestStopTransaction = "RequestStopTransaction"
    ReservationStatusUpdate = "ReservationStatusUpdate"
    ReserveNow = "ReserveNow"
    Reset = "Reset"
    SecurityEventNotification = "SecurityEventNotification"
    SendLocalList = "SendLocalList"
    SetChargingProfile = "SetChargingProfile"
    SetDisplayMessage = "SetDisplayMessage"
    SetMonitoringBase = "SetMonitorBase"
    SetMonitoringLevel = "SetMonitoringLevel"
    SetNetworkProfile = "SetNetworkProfile"
    SetVariableMonitoring = "SetVariableMonitoring"
    SetVariables = "SetVariables"
    SignCertificate = "SignCertificate"
    StatusNotification = "StatusNotification"
    TransactionEvent = "TransactionEvent"
    TriggerMessage = "TriggerMessage"
    UnlockConnector = "UnlockConnector"
    UnpublishFirmware = "UnpublishFirmware"
    UpdateFirmware = "UpdateFirmware"

# Enums


class APNAuthenticationType(str, Enum):
    """
    APNAuthenticationEnumType is used by
    setNetworkProfileSetNetworkProfileRequest.APNType
    """
    chap = "CHAP"
    none = "NONE"
    pap = "PAP"
    auto = "AUTO"


class AttributeType(str, Enum):
    """
    AttributeEnumType is used by Common:VariableAttributeType,
    getVariables:GetVariablesRequest.GetVariableDataType ,
    getVariables:GetVariablesResponse.GetVariableResultType ,
    setVariables:SetVariablesRequest.SetVariableDataType ,
    setVariables:SetVariablesResponse.SetVariableResultType
    """
    actual = "Actual"
    target = "Target"
    min_set = "MinSet"
    max_set = "MaxSet"


class AuthorizationStatusType(str, Enum):
    """
    Elements that constitute an entry of a Local Authorization List update.
    """
    accepted = "Accepted"
    blocked = "Blocked"
    concurrent_tx = "ConcurrentTx"
    expired = "Expired"
    invalid = "Invalid"
    # Identifier is valid, but EV Driver doesn’t have enough credit to start
    # charging. Not allowed for charging.
    no_credit = "NoCredit"
    # Identifier is valid, but not allowed to charge in this type of EVSE.
    not_allowed_type_evse = "NotAllowedTypeEVSE"
    not_at_this_location = "NotAtThisLocation"
    not_at_this_time = "NotAtThisTime"
    unknown = "Unknown"


class BootReasonType(str, Enum):
    """
    BootReasonEnumType is used by bootNotificationBootNotificationRequest
    """
    application_reset = "ApplicationReset"
    firmware_update = "FirmwareUpdate"
    local_reset = "LocalReset"
    power_up = "PowerUp"
    remote_reset = "RemoteReset"
    scheduled_reset = "ScheduledReset"
    triggered = "Triggered"
    unknown = "Unknown"
    watchdog = "Watchdog"


class CertificateStatusType(str, Enum):
    """
    Status of the EV Contract certificate.
    """
    accepted = "Accepted"
    signature_error = "SignatureError"
    certificate_expired = "CertificateExpired"
    certificate_revoked = "CertificateRevoked"
    no_certificate_available = "NoCertificateAvailable"
    cert_chain_error = "CertChainError"
    contract_cancelled = "ContractCancelled"


class ChargingLimitSourceType(str, Enum):
    """
    Enumeration for indicating from which source a charging limit originates.
    """
    ems = "EMS"
    other = "Other"
    so = "SO"
    cso = "CSO"


class ChargingProfileKindType(str, Enum):
    """
    "Absolute" Schedule periods are relative to a fixed point in time defined
                in the schedule.
    "Recurring" Schedule restarts periodically at the first schedule period.
    "Relative" Schedule periods are relative to a situation- specific start
                point(such as the start of a session)
    """
    absolute = "Absolute"
    recurring = "Recurring"
    relative = "Relative"


class ChargingProfilePurposeType(str, Enum):
    """
    In load balancing scenarios, the Charge Point has one or more local
    charging profiles that limit the power or current to be shared by all
    connectors of the Charge Point. The Central System SHALL configure such
    a profile with ChargingProfilePurpose set to “ChargePointMaxProfile”.
    ChargePointMaxProfile can only be set at Charge Point ConnectorId 0.

    Default schedules for new transactions MAY be used to impose charging
    policies. An example could be a policy that prevents charging during
    the day. For schedules of this purpose, ChargingProfilePurpose SHALL
    be set to TxDefaultProfile. If TxDefaultProfile is set to ConnectorId 0,
    the TxDefaultProfile is applicable to all Connectors. If ConnectorId is
    set >0, it only applies to that specific connector. In the event a
    TxDefaultProfile for connector 0 is installed, and the Central
    System sends a new profile with ConnectorId >0, the TxDefaultProfile
    SHALL be replaced only for that specific connector.

    If a transaction-specific profile with purpose TxProfile is present,
    it SHALL overrule the default charging profile with purpose
    TxDefaultProfile for the duration of the current transaction only.
    After the transaction is stopped, the profile SHOULD be deleted.
    If there is no transaction active on the connector specified in a
    charging profile of type TxProfile, then the Charge Point SHALL
    discard it and return an error status in SetChargingProfileResponse.
    TxProfile SHALL only be set at Charge Point ConnectorId >0.

    It is not possible to set a ChargingProfile with purpose set to
    TxProfile without presence of an active transaction, or in advance of
    a transaction.

    In order to ensure that the updated charging profile applies only to the
    current transaction, the chargingProfilePurpose of the ChargingProfile
    MUST be set to TxProfile.
    """
    charging_station_external_constraints = "ChargingStationExternalConstraints"
    charging_station_max_profile = "ChargingStationMaxProfile"
    tx_default_profile = "TxDefaultProfile"
    tx_profile = "TxProfile"


class ChargingRateUnitType(str, Enum):
    """
    Unit in which a charging schedule is defined, as used in
    GetCompositeSchedule.req and ChargingSchedule
    """
    w = "W"
    a = "A"


class ChargingStateType(str, Enum):
    """
    The state of the charging process.
    """
    charging = "Charging"
    evdetected = "EVDetected"
    suspended_ev = "SuspendedEV"
    suspended_evse = "SuspendedEVSE"


class ClearMonitoringStatusType(str, Enum):
    """
    ClearMonitoringStatusEnumType is used by CommonClearMonitoringResultType
    """
    accepted = "Accepted"
    rejected = "Rejected"
    not_found = "NotFound"


class ComponentCriterionType(str, Enum):
    """
    ComponentCriterionEnumType is used by getReportGetReportRequest
    """
    active = "Active"
    available = "Available"
    enabled = "Enabled"
    problem = "Problem"


class ConnectorType(str, Enum):
    """
    Allowed values of ConnectorCode.
    """
    # Combined Charging System 1 (captive cabled) a.k.a. Combo 1
    c_ccs1 = "cCCS1"
    # Combined Charging System 2 (captive cabled) a.k.a. Combo 2
    c_ccs2 = "cCCS2"
    # JARI G105-1993 (captive cabled) a.k.a. CHAdeMO
    c_g105 = "cG105"
    # Tesla Connector (captive cabled)
    c_tesla = "cTesla"
    # IEC62196-2 Type 1 connector (captive cabled) a.k.a. J1772
    c_type1 = "cType1"
    # IEC62196-2 Type 2 connector (captive cabled) a.k.a. Mennekes connector
    c_type2 = "cType2"
    # 16A 1 phase IEC60309 socket
    s309_1_p_16_a = "s309-1P-16A"
    s309_1_p_32_a = "s309-1P-32A"
    s309_3_p_16_a = "s309-3P-16A"
    s309_3_p_32_a = "s309-3P-32A"
    s_bs1361 = "sBS1361"
    s_cee_7_7 = "sCEE-7-7"
    s_type2 = "sType2"
    s_type3 = "sType3"
    other1_ph_max16_a = "Other1PhMax16A"
    other1_ph_over16_a = "Other1PhOver16A"
    other3_ph = "Other3Ph"
    pan = "Pan"
    w_inductive = "wInductive"
    w_resonant = "wResonant"
    undetermined = "Undetermined"
    unknown = "Unknown"


class CostKindType(str, Enum):
    """
    CostKindEnumType is used by CommonCostType
    """
    carbon_dioxide_emission = "CarbonDioxideEmission"
    relative_price_percentage = "RelativePricePercentage"
    renewable_generation_percentage = "RenewableGenerationPercentage"


class DataType(str, Enum):
    """
    DataEnumType is used by CommonVariableCharacteristicsType
    """
    string = "string"
    decimal = "decimal"
    integer = "integer"
    date_time = "dateTime"
    boolean = "boolean"
    option_list = "OptionList"
    sequence_list = "SequenceList"
    member_list = "MemberList"


class EncodingMethodType(str, Enum):
    other = "Other"
    dlms_message = "DLMS Message"
    cosem_protected_data = "COSEM Protected Data"
    edl = "EDL"


class EnergyTransferModeType(str, Enum):
    """
    Enumeration of energy transfer modes.
    """
    ac_single_phase_core = "AC_single_phase_core"
    ac_three_phase_core = "AC_three_phase_core"
    dc_combo_core = "DC_combo_core"
    dc_core = "DC_core"
    dc_extended = "DC_extended"
    dc_unique = "DC_unique"


class EventTriggerType(str, Enum):
    """
    EventTriggerEnumType is used by
    notifyEventNotifyEventRequest.EventDataType
    """
    alerting = "Alerting"
    delta = "Delta"
    periodic = "Periodic"


class GetCompositeScheduleStatusType(str, Enum):
    accepted = "Accepted"
    rejected = "Rejected"


class GetInstalledCertificateStatusType(str, Enum):
    """
    GetInstalledCertificateStatusEnumType is used by
    getInstalledCertificateIdsGetInstalledCertificateIdsResponse
    """
    accepted = "Accepted"
    not_found = "NotFound"


class GetVariableStatusType(str, Enum):
    """
    GetVariableStatusEnumType is used by
    getVariablesGetVariablesResponse.GetVariableResultType
    """
    accepted = "Accepted"
    rejected = "Rejected"
    unknown_component = "UnknownComponent"
    unknown_variable = "UnknownVariable"
    not_supported_attribute_type = "NotSupportedAttributeType"


class HashAlgorithmType(str, Enum):
    """
    HashAlgorithmEnumType is used by
    CommonCertificateHashDataType , CommonOCSPRequestDataType
    """
    sha256 = "SHA256"
    sha384 = "SHA384"
    sha512 = "SHA512"


class IdTokenType(str, Enum):
    """
    Allowable values of the IdTokenType field.
    """
    central = "Central"
    e_maid = "eMAID"
    iso14443 = "ISO14443"
    key_code = "KeyCode"
    local = "Local"
    no_authorization = "NoAuthorization"
    iso15693 = "ISO15693"


class LocationType(str, Enum):
    """
    Allowable values of the optional "location" field of a value element in
    SampledValue.
    """
    body = "Body"
    cable = "Cable"
    ev = "EV"
    inlet = "Inlet"
    outlet = "Outlet"


class LogType(str, Enum):
    """
    LogEnumType is used by getLogGetLogRequest
    """
    diagnostics_log = "DiagnosticsLog"
    security_log = "SecurityLog"


class MeasurandType(str, Enum):
    """
    Allowable values of the optional "measurand" field of a Value element, as
    used in MeterValues.req and StopTransaction.req messages. Default value of
    "measurand" is always "Energy.Active.Import.Register"
    """
    current_export = "Current.Export"
    current_import = "Current.Import"
    current_offered = "Current.Offered"
    energy_active_export_register = "Energy.Active.Export.Register"
    energy_active_import_register = "Energy.Active.Import.Register"
    energy_reactive_export_register = "Energy.Reactive.Export.Register"
    energy_reactive_import_register = "Energy.Reactive.Import.Register"
    energy_active_export_interval = "Energy.Active.Export.Interval"
    energy_active_import_interval = "Energy.Active.Import.Interval"
    energy_active_net = "Energy.Active.Net"
    energy_reactive_export_interval = "Energy.Reactive.Export.Interval"
    energy_reactive_import_interval = "Energy.Reactive.Import.Interval"
    energy_reactive_net = "Energy.Reactive.Net"
    energy_apparent_net = "Energy.Apparent.Net"
    energy_apparent_import = "Energy.Apparent.Import"
    energy_apparent_export = "Energy.Apparent.Export"
    frequency = "Frequency"
    power_active_export = "Power.Active.Export"
    power_active_import = "Power.Active.Import"
    power_factor = "Power.Factor"
    power_offered = "Power.Offered"
    power_reactive_export = "Power.Reactive.Export"
    power_reactive_import = "Power.Reactive.Import"
    so_c = "SoC"
    voltage = "Voltage"


class MessageFormatType(str, Enum):
    """
    Format of a message to be displayed on the display of the Charging Station.
    """
    ascii = "ASCII"
    html = "HTML"
    uri = "URI"
    utf8 = "UTF8"


class MessagePriorityType(str, Enum):
    """
    Priority with which a message should be displayed on a Charging Station.
    """
    always_front = "AlwaysFront"
    in_front = "InFront"
    normal_cycle = "NormalCycle"


class MessageStateType(str, Enum):
    """
    State of the Charging Station during which a message SHALL be displayed.
    """
    charging = "Charging"
    faulted = "Faulted"
    idle = "Idle"
    unavailable = "Unavailable"


class MessageTriggerType(str, Enum):
    """
    Type of request to be triggered in a TriggerMessage.req
    """
    boot_notification = "BootNotification"
    log_status_notification = "LogStatusNotification"
    firmware_status_notification = "FirmwareStatusNotification"
    heartbeat = "Heartbeat"
    meter_values = "MeterValues"
    sign_charging_station_certificate = "SignChargingStationCertificate"
    sign_v2_gcertificate = "SignV2GCertificate"
    status_notification = "StatusNotification"
    transaction_event = "TransactionEvent"


class MonitorType(str, Enum):
    """
    MonitorEnumType is used by CommonVariableMonitoringType
    """
    upper_threshold = "UpperThreshold"
    lower_threshold = "LowerThreshold"
    delta = "Delta"
    periodic = "Periodic"
    periodic_clock_aligned = "PeriodicClockAligned"


class MonitoringCriterionType(str, Enum):
    """
    MonitoringCriterionEnumType is used by
    getMonitoringReportGetMonitoringReportRequest
    """
    threshold_monitoring = "ThresholdMonitoring"
    delta_monitoring = "DeltaMonitoring"
    periodic_monitoring = "PeriodicMonitoring"


class MutabilityType(str, Enum):
    """
    MutabilityEnumType is used by CommonVariableAttributeType
    """
    read_only = "ReadOnly"
    write_only = "WriteOnly"
    read_write = "ReadWrite"


class OCPPInterfaceType(str, Enum):
    """
    Enumeration of network interfaces.
    """
    wired0 = "Wired0"
    wired1 = "Wired1"
    wired2 = "Wired2"
    wired3 = "Wired3"
    wireless0 = "Wireless0"
    wireless1 = "Wireless1"
    wireless2 = "Wireless2"
    wireless3 = "Wireless3"


class OCPPTransportType(str, Enum):
    """
    Enumeration of OCPP transport mechanisms.
    SOAP is currently not a valid value for OCPP 2.0.
    """
    json = "JSON"
    soap = "SOAP"


class OCPPVersionType(str, Enum):
    """
    Enumeration of OCPP transport mechanisms.
    SOAP is currently not a valid value for OCPP 2.0.
    """
    ocpp12 = "OCPP12"
    ocpp15 = "OCPP15"
    ocpp16 = "OCPP16"
    ocpp20 = "OCPP20"


class PhaseType(str, Enum):
    """
    Phase as used in SampledValue. Phase specifies how a measured value is to
    be interpreted. Please note that not all values of Phase are applicable to
    all Measurands.
    """
    l1 = "L1"
    l2 = "L2"
    l3 = "L3"
    n = "N"
    l1_n = "L1-N"
    l2_n = "L2-N"
    l3_n = "L3-N"
    l1_l2 = "L1-L2"
    l2_l3 = "L2-L3"
    l3_l1 = "L3-L1"


class ReadingContextType(str, Enum):
    """
    Values of the context field of a value in SampledValue.
    """
    interruption_begin = "Interruption.Begin"
    interruption_end = "Interruption.End"
    other = "Other"
    sample_clock = "Sample.Clock"
    sample_periodic = "Sample.Periodic"
    transaction_begin = "Transaction.Begin"
    transaction_end = "Transaction.End"
    trigger = "Trigger"


class ReasonType(str, Enum):
    """
    Reason for stopping a transaction in StopTransactionRequest
    """
    de_authorized = "DeAuthorized"
    emergency_stop = "EmergencyStop"
    energy_limit_reached = "EnergyLimitReached"
    evdisconnected = "EVDisconnected"
    ground_fault = "GroundFault"
    immediate_reset = "ImmediateReset"
    local = "Local"
    local_out_of_credit = "LocalOutOfCredit"
    master_pass = "MasterPass"
    other = "Other"
    overcurrent_fault = "OvercurrentFault"
    power_loss = "PowerLoss"
    power_quality = "PowerQuality"
    reboot = "Reboot"
    remote = "Remote"
    soclimit_reached = "SOCLimitReached"
    stopped_by_ev = "StoppedByEV"
    time_limit_reached = "TimeLimitReached"
    timeout = "Timeout"
    unlock_command = "UnlockCommand"


class RecurrencyKindType(str, Enum):
    """
    "Daily" The schedule restarts at the beginning of the next day.
    "Weekly" The schedule restarts at the beginning of the next week
              (defined as Monday morning)
    """
    daily = "Daily"
    weekly = "Weekly"


class SetMonitoringStatusType(str, Enum):
    """
    Status in SetVariableMonitoringResponse
    """
    accepted = "Accepted"
    unknown_component = "UnknownComponent"
    unknown_variable = "UnknownVariable"
    unsupported_monitor_type = "UnsupportedMonitorType"
    rejected = "Rejected"
    out_of_range = "OutOfRange"
    duplicate = "Duplicate"


class SetVariableStatusType(str, Enum):
    """
    Status in ChangeConfigurationResponse.
    """
    accepted = "Accepted"
    rejected = "Rejected"
    invalid_value = "InvalidValue"
    unknown_component = "UnknownComponent"
    unknown_variable = "UnknownVariable"
    not_supported_attribute_type = "NotSupportedAttributeType"
    out_of_range = "OutOfRange"
    reboot_required = "RebootRequired"


class SignatureMethodType(str, Enum):
    ecdsap256_sha256 = "ECDSAP256SHA256"
    ecdsap384_sha384 = "ECDSAP384SHA384"
    ecdsa192_sha256 = "ECDSA192SHA256"


class TransactionEventType(str, Enum):
    """
    Type of Event in TransactionEventRequest
    """
    ended = "Ended"
    started = "Started"
    updated = "Updated"


class TriggerReasonType(str, Enum):
    """
    Reason that triggered a transactionEventRequest
    """
    authorized = "Authorized"
    cable_plugged_in = "CablePluggedIn"
    charging_rate_changed = "ChargingRateChanged"
    charging_state_changed = "ChargingStateChanged"
    deauthorized = "Deauthorized"
    energy_limit_reached = "EnergyLimitReached"
    evcommunication_lost = "EVCommunicationLost"
    evconnect_timeout = "EVConnectTimeout"
    meter_value_clock = "MeterValueClock"
    meter_value_periodic = "MeterValuePeriodic"
    time_limit_reached = "TimeLimitReached"
    trigger = "Trigger"
    unlock_command = "UnlockCommand"
    stop_authorized = "StopAuthorized"
    evdeparted = "EVDeparted"
    evdetected = "EVDetected"
    remote_stop = "RemoteStop"
    remote_start = "RemoteStart"


class UpdateType(str, Enum):
    """
    Type of update for a SendLocalList Request.
    """
    differential = "Differential"
    full = "Full"


class VPNType(str, Enum):
    """
    Enumeration of VPN Types used in SetNetworkProfileRequest.VPNType
    """
    ikev2 = "IKEv2"
    ipsec = "IPSec"
    l2_tp = "L2TP"
    pptp = "PPTP"
