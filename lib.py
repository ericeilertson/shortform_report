"""
A simple library for generating the short form JSON report. This script is 
intended to be used by Security Review Providers who are participating in the
Open Compute Project's Firmware Security Review Framework.

The script complies with version 0.2 (draft) of the Security Review Framework.

More details can be found here: https://www.opencompute.org/wiki/Security

For example usage of this script, refer to the following.
  * sample_report.json
      An example JSON report that could be created by this library.
  * example_generate.py: 
      Demonstrates how to generate the JSON and sign it, producing a JWT.
  * example_verify.py:
      Demonstrates how to verify the signature of the JWT.

Author: Jeremy Boone, NCC Group
Date  : June 5th, 2023
"""
import json
import jwt

# TODO: In the next version of the Security Review Framework specification, we
# may want to more strictly limit the types of values that certain fields can
# hold. For example:
#   1. The 'category' could be restricted to: storage, network, cpu, etc...
#   2. The 'methodology' could be restricted to: whitebox, blackbox, etc...

# TODO: We may also want to add other fields, such as:
#   1. scope: to briefly specify the scope of the audit, secure boot, etc...



# FIXME: Expand accepted list of hash algorithms
FW_HASH_ALGOS = ("sha2_384",)


class ShortFormReport( object ):
    def __init__( self, framework_ver="0.2" ):
        self.report = {}
        self.report["review_framework_version"] = f"{framework_ver}"


    def add_device( self, vendor, product, category, fw_ver, hash_algo, fw_hash ):
        """Add metadata that describes the vendor's device that was tested.
        
        vendor:    The name of the vendor that manufactured the device.
        product:   The name of the device. Usually a model name or number.
        category:  The type of device that was audited. Usually a short string 
                     such as: 'storage', 'network', or 'cpu'.
        fw_ver:    The version of the firmware image that that is attested by
                     this report. In most cases this will be the firmware version
                     produced by the vendor after the security audit completes,
                     which contains fixes for all vulnerabilities found during
                     the audit.
        hash_algo: The algorithm used to calculate the firmware hash. Must be
                     one of those specified in `FW_HASH_ALGOS`.
        fw_hash:   A hex-encoded string containing the hash of the firmware image.
        """
        if hash_algo not in FW_HASH_ALGOS:
            raise ValueError(f"fw_hash_algo '{hash_algo}' must be one of: {FW_HASH_ALGOS}")
        
        self.report["device"] = {}
        self.report["device"]["vendor"]       = f"{vendor}".strip()
        self.report["device"]["product"]      = f"{product}".strip()
        self.report["device"]["category"]     = f"{category}".strip()
        self.report["device"]["fw_version"]   = f"{fw_ver}".strip()
        self.report["device"]["fw_hash_algo"] = f"{hash_algo}".strip()
        self.report["device"]["fw_hash"]      = f"{fw_hash}".strip()


    def add_audit( self, srp, methodology, date, report_ver, cvss_ver="3.1" ):
        """Add metadata that describes the scope of the security review.
        
        srp:             The name of the Security Review Provider.
        methodology:     The test methodology. Currently a free-form text field.
                           Usually a value like 'whitebox' or 'blackbox'.
        completion_date: In the YYY-MM-DD format.
        report_version:  Version of the report created by the SRP.
        cvss_version:    Version of CVSS used to calculate scores for each issue.
                           Defaults to CVSS v3.1.
        """
        self.report["audit"] = {}
        self.report["audit"]["srp"]             = f"{srp}".strip()
        self.report["audit"]["methodology"]     = f"{methodology}".strip()
        self.report["audit"]["completion_date"] = f"{date}".strip()
        self.report["audit"]["report_version"]  = f"{report_ver}".strip()
        self.report["audit"]["cvss_version"]    = f"{cvss_ver}".strip()
        self.report["audit"]["issues"]          = []


    def add_issue( self, title, cvss_score, cvss_vec, cwe, description, cve=None ):
        """Add one issue to the list of issues. This list should only contain
        unfixed issues. That is, any vulnerabilities discovered during the
        audit that were fixed before the 'fw_version' (listed above) should not
        be included.
        
        title:       A brief summary of the issue. Usually taken directly from 
                       the SRP's audit report.
        cvss_score:  The CVSS base score, represented as a string, such as "7.1".
        cvss_vec:    The CVSS base vector. Temporal and environmental metrics are
                       not used or tracked.
        cwe:         The CWE identifier for the vulnerability, for example "CWE-123".
        description: A one or two sentence description of the issue. All device
                       vendor sensitive information should be redacted.
        cve:         This field is optional, as not all reported issues will be
                       assigned a CVE number.
        """
        new_issue = {
          "title":       f"{title}".strip(),
          "cvss_score":  f"{cvss_score}".strip(),
          "cvss_vector": f"{cvss_vec}".strip(),
          "cwe":         f"{cwe}".strip(),
          "description": f"{description}".strip(),
        }

        if cve is None: new_issue["cve"] = None
        else:           new_issue["cve"] = f"{cve}".strip()
            
        self.report["audit"]["issues"].append( new_issue )


    def get_report( self ):
        """Print the short-form report as a Python dict, which can be converted to JSON.
        """
        return self.report


    def print_report( self ):
        """Prints the short-form JSON report
        """
        print( json.dumps( self.get_report(), indent=4 ) ) 


    def sign_report( self, priv_key ):
        """Sign the JSON object to make the JWT.
        """
        self.signed_report = jwt.encode( self.get_report(), key=priv_key, algorithm="RS512" )
        return self.signed_report


    def get_signed_report( self ):
        """Print the signed short form report (a JWT).
        """
        return self.signed_report 



