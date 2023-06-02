import json
import datetime
from ecdsa import SigningKey, NIST384p, VerifyingKey


def verify_report(report_json):
    document = json.loads(report_json)
    vk = VerifyingKey.from_der(bytearray.fromhex(document["verify_key"]))
    report = document['report']
    report_string = str.encode(json.dumps(report, indent=4))
    signature = bytearray.fromhex(document['signature_hex'])
    result = vk.verify(signature, report_string)
    print(result)
    return result


def main():
    vendor_name = "Vendor Name"
    firmware_hash_sha2_384 = "0xabcdef..."
    firmware_version = "1.2.4.f"
    published_cves = [{
        "name": "some name",
        "score": 5.9,
        "disputed": True,
        "description": "** DISPUTED ** This is a description of the finding from the NIST vulnerability website",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
    },
        {
            "name": "some other name",
            "description": "This is a description of another vulnerability from the NIST website",
            "score": 7.5,
            "disputed": False,
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-1234"
        }
    ]
    audit_cves = [{"name": "some brief name",
                   "score": 9.3,
                   "disputed": False,
                   "description": "a description of the vulnerability the auditor has discovered"
                   }]

    report = {"component_vendor": vendor_name,
              "firmware_version": firmware_version,
              "auditor_name": "the company that performed the audit",
              "review_type": "white box",
              "scope_document_revision": 1.4,
              "audit_date": "%s" % datetime.datetime.now(),
              "product name/category": "CPU supreme",
              "firmware_hash_sha2_384": firmware_hash_sha2_384,
              "published_cves": published_cves,
              "audit_cves": audit_cves,
              }
    document_string = str.encode(json.dumps(report, indent=4))
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    signature = sk.sign(document_string).hex()
    final_doc = {"report": report, 'signature_hex': signature, 'verify_key': vk.to_der().hex()}
    final_doc_string = json.dumps(final_doc, indent=4)
    print(final_doc_string)

    valid = verify_report(final_doc_string)
    print("Valid: %s" % valid)

    # final_doc['report']['make_different'] = "this should fail now"
    # final_doc = {"report": report, 'signature_hex': signature, 'verify_key': vk.to_der().hex()}
    # final_doc_string = json.dumps(final_doc, indent=4)
    # valid = verify_report(final_doc_string)
    # print("Valid: %s" % valid)


if __name__ == '__main__':
    main()
