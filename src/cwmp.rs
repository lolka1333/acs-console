//! cwmp.rs — CWMP/TR-069 SOAP message construction and parsing (port of cwmp.py).
//!
//! Build side: hand-rolled string templates byte-faithful to the real RV6699
//! cwmp client (verified against the firmware binary): uppercase SOAP-ENV/
//! SOAP-ENC prefixes, exactly 5 xmlns decls, no encodingStyle, and the
//! mandatory cwmp:ID mustUnderstand header.
//!
//! Parse side: roxmltree, matching by local-name so we are namespace-agnostic
//! (the CPE may use SOAP-ENV / soapenv / soap prefixes and cwmp-1-0..1-4).

use roxmltree::{Document, Node};

// --- namespace URIs ---------------------------------------------------------
pub const SOAP_ENV: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const SOAP_ENC: &str = "http://schemas.xmlsoap.org/soap/encoding/";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema";
pub const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub const CWMP_DEFAULT: &str = "urn:dslforum-org:cwmp-1-0";

/// parameters whose xsi:type is not plain string (best-effort).
fn known_type(leaf: &str) -> Option<&'static str> {
    match leaf {
        "PeriodicInformInterval" => Some("xsd:unsignedInt"),
        "PeriodicInformEnable" => Some("xsd:boolean"),
        "EnableCWMP" => Some("xsd:boolean"),
        "DefaultActiveNotificationThrottle" => Some("xsd:unsignedInt"),
        "CWMPRetryMinimumWaitInterval" => Some("xsd:unsignedInt"),
        "CWMPRetryIntervalMultiplier" => Some("xsd:unsignedInt"),
        "UpgradesManaged" => Some("xsd:boolean"),
        "STUNEnable" => Some("xsd:boolean"),
        "Enable" => Some("xsd:boolean"),
        "DHCPServerEnable" => Some("xsd:boolean"),
        "RadioEnabled" => Some("xsd:boolean"),
        "Channel" => Some("xsd:unsignedInt"),
        _ => None,
    }
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn guess_type(name: &str) -> String {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    known_type(leaf).unwrap_or("xsd:string").to_string()
}

// --- envelope ---------------------------------------------------------------
/// Wrap one RPC body element in a complete SOAP 1.1 / CWMP envelope.
pub fn envelope(body_inner: &str, cwmp_id: &str, cwmp_ns: &str) -> Vec<u8> {
    // Byte-faithful to the real RV6699 cwmp client (gSOAP/iXML): uppercase
    // SOAP-ENV/SOAP-ENC prefixes, exactly these 5 xmlns decls, and NO
    // encodingStyle attribute (the device emits none and its parser ignores
    // extras; matching it also hits the broadest gSOAP fast-paths).
    let doc = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<SOAP-ENV:Envelope \
xmlns:SOAP-ENV=\"{SOAP_ENV}\" \
xmlns:SOAP-ENC=\"{SOAP_ENC}\" \
xmlns:xsd=\"{XSD}\" \
xmlns:xsi=\"{XSI}\" \
xmlns:cwmp=\"{ns}\">\
<SOAP-ENV:Header>\
<cwmp:ID SOAP-ENV:mustUnderstand=\"1\">{id}</cwmp:ID>\
</SOAP-ENV:Header>\
<SOAP-ENV:Body>{body}</SOAP-ENV:Body>\
</SOAP-ENV:Envelope>",
        SOAP_ENV = SOAP_ENV,
        SOAP_ENC = SOAP_ENC,
        XSD = XSD,
        XSI = XSI,
        ns = cwmp_ns,
        id = xml_escape(cwmp_id),
        body = body_inner,
    );
    doc.into_bytes()
}

// --- ACS -> CPE request builders -------------------------------------------
pub fn get_parameter_values(names: &[String]) -> String {
    let items: String = names
        .iter()
        .map(|n| format!("<string>{}</string>", xml_escape(n)))
        .collect();
    format!(
        "<cwmp:GetParameterValues><ParameterNames \
SOAP-ENC:arrayType=\"xsd:string[{n}]\">{items}\
</ParameterNames></cwmp:GetParameterValues>",
        n = names.len(),
        items = items,
    )
}

/// params: list of (name, value, xsi_type|empty).
pub fn set_parameter_values(params: &[(String, String, String)], parameter_key: &str) -> String {
    let rows: String = params
        .iter()
        .map(|(name, value, xtype)| {
            let xtype = if xtype.is_empty() {
                guess_type(name)
            } else {
                xtype.clone()
            };
            format!(
                "<ParameterValueStruct><Name>{name}</Name>\
<Value xsi:type=\"{xtype}\">{value}</Value>\
</ParameterValueStruct>",
                name = xml_escape(name),
                xtype = xtype,
                value = xml_escape(value),
            )
        })
        .collect();
    format!(
        "<cwmp:SetParameterValues><ParameterList \
SOAP-ENC:arrayType=\"cwmp:ParameterValueStruct[{n}]\">{rows}\
</ParameterList><ParameterKey>{pk}</ParameterKey>\
</cwmp:SetParameterValues>",
        n = params.len(),
        rows = rows,
        pk = xml_escape(parameter_key),
    )
}

pub fn get_parameter_names(path: &str, next_level: bool) -> String {
    let nl = if next_level { "true" } else { "false" };
    format!(
        "<cwmp:GetParameterNames><ParameterPath>{path}</ParameterPath>\
<NextLevel>{nl}</NextLevel></cwmp:GetParameterNames>",
        path = xml_escape(path),
        nl = nl,
    )
}

pub fn get_parameter_attributes(names: &[String]) -> String {
    let items: String = names
        .iter()
        .map(|n| format!("<string>{}</string>", xml_escape(n)))
        .collect();
    format!(
        "<cwmp:GetParameterAttributes><ParameterNames \
SOAP-ENC:arrayType=\"xsd:string[{n}]\">{items}\
</ParameterNames></cwmp:GetParameterAttributes>",
        n = names.len(),
        items = items,
    )
}

/// items: list of (name, notification, notification_change, access_list|None).
pub struct AttrItem {
    pub name: String,
    pub notification: i64,
    pub notification_change: bool,
    pub access_list: Option<Vec<String>>,
}

pub fn set_parameter_attributes(items: &[AttrItem]) -> String {
    let rows: String = items
        .iter()
        .map(|it| {
            let al_change = if it.access_list.is_some() {
                "true"
            } else {
                "false"
            };
            let empty: Vec<String> = Vec::new();
            let al = it.access_list.as_ref().unwrap_or(&empty);
            let al_xml: String = al
                .iter()
                .map(|a| format!("<string>{}</string>", xml_escape(a)))
                .collect();
            format!(
                "<SetParameterAttributesStruct>\
<Name>{name}</Name>\
<NotificationChange>{nc}</NotificationChange>\
<Notification>{notif}</Notification>\
<AccessListChange>{alc}</AccessListChange>\
<AccessList SOAP-ENC:arrayType=\"xsd:string[{aln}]\">{al_xml}</AccessList>\
</SetParameterAttributesStruct>",
                name = xml_escape(&it.name),
                nc = if it.notification_change {
                    "true"
                } else {
                    "false"
                },
                notif = it.notification,
                alc = al_change,
                aln = al.len(),
                al_xml = al_xml,
            )
        })
        .collect();
    format!(
        "<cwmp:SetParameterAttributes><ParameterList \
SOAP-ENC:arrayType=\"cwmp:SetParameterAttributesStruct[{n}]\">{rows}\
</ParameterList></cwmp:SetParameterAttributes>",
        n = items.len(),
        rows = rows,
    )
}

pub fn add_object(object_name: &str, parameter_key: &str) -> String {
    format!(
        "<cwmp:AddObject><ObjectName>{on}</ObjectName>\
<ParameterKey>{pk}</ParameterKey></cwmp:AddObject>",
        on = xml_escape(object_name),
        pk = xml_escape(parameter_key),
    )
}

pub fn delete_object(object_name: &str, parameter_key: &str) -> String {
    format!(
        "<cwmp:DeleteObject><ObjectName>{on}</ObjectName>\
<ParameterKey>{pk}</ParameterKey></cwmp:DeleteObject>",
        on = xml_escape(object_name),
        pk = xml_escape(parameter_key),
    )
}

pub fn reboot(command_key: &str) -> String {
    format!(
        "<cwmp:Reboot><CommandKey>{ck}</CommandKey></cwmp:Reboot>",
        ck = xml_escape(command_key),
    )
}

pub fn factory_reset() -> String {
    "<cwmp:FactoryReset></cwmp:FactoryReset>".to_string()
}

pub fn get_rpc_methods() -> String {
    "<cwmp:GetRPCMethods></cwmp:GetRPCMethods>".to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn download(
    command_key: &str,
    file_type: &str,
    url: &str,
    username: &str,
    password: &str,
    file_size: i64,
    target_filename: &str,
    delay_seconds: i64,
    success_url: &str,
    failure_url: &str,
) -> String {
    format!(
        "<cwmp:Download>\
<CommandKey>{ck}</CommandKey>\
<FileType>{ft}</FileType>\
<URL>{url}</URL>\
<Username>{user}</Username>\
<Password>{pass}</Password>\
<FileSize>{fs}</FileSize>\
<TargetFileName>{tf}</TargetFileName>\
<DelaySeconds>{ds}</DelaySeconds>\
<SuccessURL>{su}</SuccessURL>\
<FailureURL>{fu}</FailureURL>\
</cwmp:Download>",
        ck = xml_escape(command_key),
        ft = xml_escape(file_type),
        url = xml_escape(url),
        user = xml_escape(username),
        pass = xml_escape(password),
        fs = file_size,
        tf = xml_escape(target_filename),
        ds = delay_seconds,
        su = xml_escape(success_url),
        fu = xml_escape(failure_url),
    )
}

pub fn upload(
    command_key: &str,
    file_type: &str,
    url: &str,
    username: &str,
    password: &str,
    delay_seconds: i64,
) -> String {
    format!(
        "<cwmp:Upload>\
<CommandKey>{ck}</CommandKey>\
<FileType>{ft}</FileType>\
<URL>{url}</URL>\
<Username>{user}</Username>\
<Password>{pass}</Password>\
<DelaySeconds>{ds}</DelaySeconds>\
</cwmp:Upload>",
        ck = xml_escape(command_key),
        ft = xml_escape(file_type),
        url = xml_escape(url),
        user = xml_escape(username),
        pass = xml_escape(password),
        ds = delay_seconds,
    )
}

// --- CPE -> ACS response builders ------------------------------------------
pub fn inform_response() -> String {
    "<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>".to_string()
}

pub fn transfer_complete_response() -> String {
    "<cwmp:TransferCompleteResponse></cwmp:TransferCompleteResponse>".to_string()
}

pub fn autonomous_transfer_complete_response() -> String {
    "<cwmp:AutonomousTransferCompleteResponse></cwmp:AutonomousTransferCompleteResponse>"
        .to_string()
}

pub fn get_rpc_methods_response(methods: &[&str]) -> String {
    let items: String = methods
        .iter()
        .map(|m| format!("<string>{}</string>", xml_escape(m)))
        .collect();
    format!(
        "<cwmp:GetRPCMethodsResponse><MethodList \
SOAP-ENC:arrayType=\"xsd:string[{n}]\">{items}\
</MethodList></cwmp:GetRPCMethodsResponse>",
        n = methods.len(),
        items = items,
    )
}

pub const ACS_RPC_METHODS: [&str; 4] = [
    "GetRPCMethods",
    "Inform",
    "TransferComplete",
    "AutonomousTransferComplete",
];

// --- parsed message types ---------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct ParamValue {
    pub name: String,
    pub value: String,
    pub type_: String,
}

#[derive(Debug, Clone, Default)]
pub struct ParamName {
    pub name: String,
    pub writable: String,
}

#[derive(Debug, Clone, Default)]
pub struct ParamAttr {
    pub name: String,
    pub notification: String,
    pub access_list: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EventStruct {
    pub code: String,
    pub command_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct SetFault {
    pub name: String,
    pub code: String,
    pub string: String,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub kind: String,
    pub id: Option<String>,
    pub cwmp_ns: String,
    pub error: Option<String>,

    // Inform
    pub device_id: std::collections::HashMap<String, String>,
    pub events: Vec<EventStruct>,
    pub parameters: Vec<ParamValue>,

    // GetParameterNamesResponse
    pub names: Vec<ParamName>,
    // GetParameterAttributesResponse
    pub attributes: Vec<ParamAttr>,

    // status-bearing responses
    pub status: Option<String>,
    pub instance_number: Option<String>,
    pub start_time: Option<String>,
    pub complete_time: Option<String>,
    pub methods: Vec<String>,

    // Fault
    pub cwmp_fault_code: String,
    pub cwmp_fault_string: String,
    pub set_faults: Vec<SetFault>,

    // TransferComplete
    pub command_key: String,
    pub fault_code: String,
    pub fault_string: String,
}

// --- parsing helpers --------------------------------------------------------
fn find_descendant<'a, 'input>(el: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    el.descendants()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn txt(el: Node, name: &str) -> String {
    match find_descendant(el, name) {
        Some(n) => n.text().unwrap_or("").trim().to_string(),
        None => String::new(),
    }
}

pub fn detect_cwmp_ns(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    // look for xmlns:xxx="urn:dslforum-org:cwmp-1-N"
    if let Some(pos) = s.find("urn:dslforum-org:cwmp-1-") {
        let tail = &s[pos..];
        // grab "urn:dslforum-org:cwmp-1-" + one digit
        let prefix_len = "urn:dslforum-org:cwmp-1-".len();
        if let Some(d) = tail[prefix_len..].chars().next()
            && d.is_ascii_digit()
        {
            return format!("urn:dslforum-org:cwmp-1-{}", d);
        }
    }
    CWMP_DEFAULT.to_string()
}

/// Parse an inbound SOAP message.
pub fn parse(raw: &[u8]) -> ParsedMessage {
    let trimmed = raw.iter().all(|b| b.is_ascii_whitespace());
    if raw.is_empty() || trimmed {
        return ParsedMessage {
            kind: "empty".to_string(),
            id: None,
            cwmp_ns: CWMP_DEFAULT.to_string(),
            ..Default::default()
        };
    }
    let cwmp_ns = detect_cwmp_ns(raw);
    let text = String::from_utf8_lossy(raw);
    let doc = match Document::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            return ParsedMessage {
                kind: "parse_error".to_string(),
                id: None,
                cwmp_ns,
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    };
    let root = doc.root_element();

    // cwmp:ID from the Header
    let mut cwmp_id: Option<String> = None;
    for el in root.descendants() {
        if el.is_element() && el.tag_name().name() == "ID" {
            cwmp_id = Some(el.text().unwrap_or("").trim().to_string());
            break;
        }
    }

    // locate Body and its first element child = the RPC
    let body = root
        .descendants()
        .find(|el| el.is_element() && el.tag_name().name() == "Body");
    let rpc = body.and_then(|b| b.children().find(|c| c.is_element()));

    let rpc = match rpc {
        Some(r) => r,
        None => {
            return ParsedMessage {
                kind: "empty".to_string(),
                id: cwmp_id,
                cwmp_ns,
                ..Default::default()
            };
        }
    };

    let name = rpc.tag_name().name().to_string();
    let mut out = ParsedMessage {
        kind: name.clone(),
        id: cwmp_id,
        cwmp_ns,
        ..Default::default()
    };

    match name.as_str() {
        "Inform" => parse_inform(rpc, &mut out),
        "Fault" => parse_fault(rpc, &mut out),
        "GetParameterValuesResponse" => {
            out.parameters = parse_value_list(rpc);
        }
        "GetParameterNamesResponse" => {
            out.names = parse_name_list(rpc);
        }
        "GetParameterAttributesResponse" => {
            out.attributes = parse_attr_list(rpc);
        }
        "SetParameterValuesResponse" => {
            out.status =
                find_descendant(rpc, "Status").map(|s| s.text().unwrap_or("").trim().to_string());
        }
        "AddObjectResponse" => {
            out.instance_number = find_descendant(rpc, "InstanceNumber")
                .map(|s| s.text().unwrap_or("").trim().to_string());
            out.status =
                find_descendant(rpc, "Status").map(|s| s.text().unwrap_or("").trim().to_string());
        }
        "DeleteObjectResponse" => {
            out.status =
                find_descendant(rpc, "Status").map(|s| s.text().unwrap_or("").trim().to_string());
        }
        "DownloadResponse" | "UploadResponse" => {
            out.status = Some(txt(rpc, "Status"));
            out.start_time = Some(txt(rpc, "StartTime"));
            out.complete_time = Some(txt(rpc, "CompleteTime"));
        }
        "GetRPCMethodsResponse" => {
            out.methods = rpc
                .descendants()
                .filter(|c| c.is_element() && c.tag_name().name() == "string")
                .map(|c| c.text().unwrap_or("").trim().to_string())
                .collect();
        }
        "GetRPCMethods" => {}
        "TransferComplete" | "AutonomousTransferComplete" => {
            parse_transfer_complete(rpc, &mut out);
        }
        _ => {}
    }
    out
}

fn parse_inform(rpc: Node, out: &mut ParsedMessage) {
    if let Some(devid) = find_descendant(rpc, "DeviceId") {
        for k in ["Manufacturer", "OUI", "ProductClass", "SerialNumber"] {
            out.device_id.insert(k.to_string(), txt(devid, k));
        }
    }
    if let Some(ev) = find_descendant(rpc, "Event") {
        for es in ev.children().filter(|c| c.is_element()) {
            if es.tag_name().name() == "EventStruct" {
                out.events.push(EventStruct {
                    code: txt(es, "EventCode"),
                    command_key: txt(es, "CommandKey"),
                });
            }
        }
    }
    out.parameters = parse_value_list(rpc);
}

fn parse_value_list(rpc: Node) -> Vec<ParamValue> {
    let mut out = Vec::new();
    let pl = match find_descendant(rpc, "ParameterList") {
        Some(p) => p,
        None => return out,
    };
    for pvs in pl.children().filter(|c| c.is_element()) {
        if pvs.tag_name().name() != "ParameterValueStruct" {
            continue;
        }
        let name = txt(pvs, "Name");
        let mut value = String::new();
        let mut xtype = String::new();
        if let Some(val_el) = find_descendant(pvs, "Value") {
            value = val_el.text().unwrap_or("").to_string();
            for a in val_el.attributes() {
                if a.name() == "type" {
                    xtype = a.value().to_string();
                }
            }
        }
        out.push(ParamValue {
            name,
            value,
            type_: xtype,
        });
    }
    out
}

fn parse_name_list(rpc: Node) -> Vec<ParamName> {
    let mut out = Vec::new();
    let pl = match find_descendant(rpc, "ParameterList") {
        Some(p) => p,
        None => return out,
    };
    for pis in pl.children().filter(|c| c.is_element()) {
        if pis.tag_name().name() != "ParameterInfoStruct" {
            continue;
        }
        out.push(ParamName {
            name: txt(pis, "Name"),
            writable: txt(pis, "Writable"),
        });
    }
    out
}

fn parse_attr_list(rpc: Node) -> Vec<ParamAttr> {
    let mut out = Vec::new();
    let pl = match find_descendant(rpc, "ParameterList") {
        Some(p) => p,
        None => return out,
    };
    for pas in pl.children().filter(|c| c.is_element()) {
        if pas.tag_name().name() != "ParameterAttributeStruct" {
            continue;
        }
        let access: Vec<String> = pas
            .descendants()
            .filter(|c| c.is_element() && c.tag_name().name() == "string")
            .map(|c| c.text().unwrap_or("").trim().to_string())
            .collect();
        out.push(ParamAttr {
            name: txt(pas, "Name"),
            notification: txt(pas, "Notification"),
            access_list: access,
        });
    }
    out
}

fn parse_fault(rpc: Node, out: &mut ParsedMessage) {
    // inner cwmp:Fault (a descendant Fault that is not rpc itself)
    let cwmp_fault = rpc
        .descendants()
        .find(|el| el.is_element() && el.tag_name().name() == "Fault" && *el != rpc);
    if let Some(cf) = cwmp_fault {
        out.cwmp_fault_code = txt(cf, "FaultCode");
        out.cwmp_fault_string = txt(cf, "FaultString");
        for c in cf.children().filter(|c| c.is_element()) {
            if c.tag_name().name() == "SetParameterValuesFault" {
                out.set_faults.push(SetFault {
                    name: txt(c, "ParameterName"),
                    code: txt(c, "FaultCode"),
                    string: txt(c, "FaultString"),
                });
            }
        }
    }
}

fn parse_transfer_complete(rpc: Node, out: &mut ParsedMessage) {
    if let Some(fs) = find_descendant(rpc, "FaultStruct") {
        out.fault_code = txt(fs, "FaultCode");
        out.fault_string = txt(fs, "FaultString");
    }
    out.command_key = txt(rpc, "CommandKey");
    out.start_time = Some(txt(rpc, "StartTime"));
    out.complete_time = Some(txt(rpc, "CompleteTime"));
}
