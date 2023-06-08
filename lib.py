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


# FIXME: Expand accepted list of signing algorithms
ALLOWED_JWT_ALGORITHMS = ("PS512",)

class ShortFormReport( object ):
    def __init__( self, framework_ver="0.2" ):
        self.report = {}
        self.report["review_framework_version"] = f"{framework_ver}".strip()
        self.signed_report = None


    def add_device( self, vendor, product, category, fw_ver, fw_hash_sha2_256, fw_hash_sha2_384, fw_hash_sha2_512 ):
        """Add metadata that describes the vendor's device that was tested.
        
        vendor:    The name of the vendor that manufactured the device.
        product:   The name of the device. Usually a model name or number.
        category:  The type of device that was audited. Usually a short string 
                     such as: 'storage', 'network', 'gpu', 'cpu', 'apu', or 'bmc'.
        fw_ver:    The version of the firmware image that that is attested by
                     this report. In most cases this will be the firmware version
                     produced by the vendor after the security audit completes,
                     which contains fixes for all vulnerabilities found during
                     the audit.
        fw_hash_sha3_256: A hex-encoded string containing the SHA2-256 hash of the firmware image.
        fw_hash_sha3_384: A hex-encoded string containing the SHA2-384 hash of the firmware image.
        fw_hash_sha3_512: A hex-encoded string containing the SHA2-512 hash of the firmware image.
        """
      
        self.report["device"] = {}
        self.report["device"]["vendor"]       = f"{vendor}".strip()
        self.report["device"]["product"]      = f"{product}".strip()
        self.report["device"]["category"]     = f"{category}".strip()
        self.report["device"]["fw_version"]   = f"{fw_ver}".strip()
        self.report["device"]["fw_hash_sha2_256"] = f"{fw_hash_sha2_256}".strip()
        self.report["device"]["fw_hash_sha2_384"] = f"{fw_hash_sha2_384}".strip()
        self.report["device"]["fw_hash_sha2_512"] = f"{fw_hash_sha2_512}".strip()
        

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


    ###########################################################################
    ## APIs for getting and printing the JSON report
    ###########################################################################
    
    def get_report_as_dict( self ):
        """Returns the short-form report as a Python dict.
        """
        return self.report
    
    def get_report_as_str( self ):
        """Return the short-form report as a formatted/indented string.
        """
        return json.dumps( self.get_report_as_dict(), indent=4 )

    def print_report( self ):
        """Pretty-prints the short-form report
        """
        print( self.get_report_as_str() ) 


    ###########################################################################
    ## APIs for signing the report
    ###########################################################################

    # TODO: ecc384 or larger, w/ p-curves
    # TODO: rsa3k or larger

    def sign_report( self, priv_key, algo ):
        """Sign the JSON object to make the JWT. Returns the JWT as a bytes object.
        
        priv_key: A string containing the private key.
        algo:     The string that specifies the algorithm, matching those in the
                    PyJWT documentation, here:
                    https://pyjwt.readthedocs.io/en/latest/algorithms.html
        """
        if algo not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError( f"Algorithm '{algo}' not in: {ALLOWED_JWT_ALGORITHMS}" )
        self.signed_report = jwt.encode( self.get_report_as_dict(), 
                                         key=priv_key,
                                         algorithm=algo )
        return self.signed_report




    def get_signed_report( self ):
        """Returns the signed short form report (a JWT). May return a 'None' 
        object if the report hasn't been signed yet.
        """
        return self.signed_report 


