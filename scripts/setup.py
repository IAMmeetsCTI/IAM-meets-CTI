import argparse, pytz, os
from stix2.v21 import Identity, Report
from stix2.v21.vocab import IDENTITY_CLASS_INDIVIDUAL, IDENTITY_CLASS_ORGANIZATION,INDUSTRY_SECTOR, REPORT_TYPE_OBSERVED_DATA, REPORT_TYPE_VULNERABILITY
from stix2.utils import STIXdatetime

# Arguments
parser = argparse.ArgumentParser(description='This script creates the setup for the IAM anomaly observations. Example: setup.py --report-name "IAM Anomaly Report 2023" --report-description "This report summarizes the results of the IAM anomaly analysis 2023" --reporter-name "John Doe" --reporter-contact joe.doe@demoCompany.com --reporter-roles "Security Analyst" "IAM Expert" --organization-name DemoCompany --organization-contact security@demoCompany.com --organization-sectors technology agriculture')
parser.add_argument('--report-name', help='Name of the analysis', required=True)
parser.add_argument('--report-description', help='Additional descrption for the analysis', required=False)
parser.add_argument('--reporter-name', help='The name of the (default) reporter', required=True)
parser.add_argument('--reporter-contact', help='The contact for the (default) reporter', required=False)
parser.add_argument('--reporter-roles', help='The roles for the (default) reporter', required=False, nargs='*')
parser.add_argument('--organization-name', help='The name of the analysed organization', required=True)
parser.add_argument('--organization-contact', help='The contact for the analysed organization', required=False)
parser.add_argument('--organization-sectors', help='The sectors for the analysed organization', required=False, choices=INDUSTRY_SECTOR, nargs='*')
parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# Create Entities
reporter = Identity(
    name=args.reporter_name,
    identity_class=IDENTITY_CLASS_INDIVIDUAL,
    contact_information=args.reporter_contact,
    roles=args.reporter_roles
)
organization = Identity(
    name=args.organization_name,
    identity_class=IDENTITY_CLASS_ORGANIZATION,
    contact_information=args.organization_contact,
    sectors=args.organization_sectors
)
report = Report(
    name=args.report_name,
    description=args.report_description,
    report_types=[REPORT_TYPE_OBSERVED_DATA, REPORT_TYPE_VULNERABILITY],
    object_refs=[reporter.id, organization.id],
    published=STIXdatetime.now(tz=pytz.UTC)
)

# Prepare Temp Dirs
path = args.out + "temp/"
isExist = os.path.exists(path)
if not isExist:
   os.makedirs(path)
for file in os.listdir(path):
    if file.endswith('.json'):
        os.remove(path+file)

# Save Entities
with open(path + "reporter.json", "w") as outfile:
    outfile.write(reporter.serialize(pretty=True))
    outfile.close
with open(path + "organization.json", "w") as outfile:
    outfile.write(organization.serialize(pretty=True))
    outfile.close
with open(path + "report.json", "w") as outfile:
    outfile.write(report.serialize(pretty=True))
    outfile.close