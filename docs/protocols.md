# Implemented protocol stack

The hospital is a Python/Flask JSON API backed by SQLite and ordinary local dummy files. It simulates hospital IT/authentication, electronic records, lab orders/results and ten medical-device telemetry identities. These are separate logical workflows rather than full clinical products.

Virtual Ethernet and IPv4 connect the Windows host and Ubuntu guest. ARP resolves local peers; TCP carries HTTP/1.1 on hospital port 8080 and export ports 9080/9081. Plain HTTP is confined to the isolated synthetic lab so packet analysis can show request headers, methods and responses. Wazuh agent communication is separately authenticated/encrypted; its dashboard uses HTTPS. The measured capture intentionally excludes Wazuh and dashboard ports.

Wireshark can show connection timing, HTTP operations and export traffic. File modification is established by actual before/after hashes and native FIM, not by a PUT packet alone. Export integrity is established by sender/receiver size and digest; wire byte counts include headers and retransmissions. TLS payload visibility would require session secrets; without them only metadata is claimed.

FHIR/HL7, DICOM and medical-device-specific protocols are possible future adapters, not implemented features. The current one-subnet lab does not demonstrate segmentation, clinical safety or regulatory compliance. Packet screenshots and query results remain pending until actual VM evaluation.
