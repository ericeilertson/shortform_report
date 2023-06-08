"""
Sample code that demonstrates how to generate, sign and verify a short-form report.

Author: Jeremy Boone
Date:   June 5th, 2023
"""
from lib import ShortFormReport
import json
import jwt
import traceback

# Construct the short form report object
rep = ShortFormReport()

# Add vendor device information
# XXX: Note to SRP: This is where you must calculate the hash of the firmware image.
rep.add_device( "ACME Inc", "Roadrunner Trap", "storage", "1.2.3", "sha2_384", 
                "0x922c72f8ae9bdad3919f501ab5894052926e53ded1c518da824f57500f8e41fda4d221341b84a753e16724840f2a9ba2" )
                
# Add audit information from Security Review Provider information
rep.add_audit( "NCC Group", "whitebox", "2023-06-25", "1.2" )

# Add issue details.
rep.add_issue( "Memory corruption when reading record from SPI flash",
               "7.9",
               "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
               "CWE-111",
               "Due to insufficient input validation in the firmware, a local" \
                   " attacker who tampers with a configuration structure in"   \
                   " SPI flash, can cause stack-based memory corruption." )

# Example of issue that has an associated CVE
rep.add_issue( "Debug commands enable arbitrary memory read/write",
			   "8.7",
			   "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
			   "CWE-222",
			   "The firmware exposes debug command handlers that enable host-side" \
			       " drivers to read and write arbitrary regions of the device's"  \
			       " SRAM.",
			   cve="CVE-2023-22222" )

# Print the short form report to console
print( "The short-form report:" )
print( rep.get_report_as_str() ) 

# Sign the short-form report (as JWT) and print to console
print( "\n\n" )
print( "The corresponding signed JWT:" )
with open( "testkey.pem","r" ) as f:
    privkey = f.read()
    signed_report = rep.sign_report( privkey, algo="PS512" )
    print( signed_report )

# Verify the signature
print( "\n\n" )
print( "Verifying signature..." )
with open( "testkey.pub", "r") as f:
    pubkey = f.read()

try:
    decoded = jwt.decode( signed_report, pubkey, algorithms=["PS512",] )
    print( "Success!" )
    print( "\n\n" )
    print( "Decoded report:" )
    print( decoded )
except Exception:
    print( "Error!" )
    traceback.print_exc()


