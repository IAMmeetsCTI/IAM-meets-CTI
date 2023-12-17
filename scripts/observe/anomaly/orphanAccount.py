import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.anomalies import ANOMALY_ORPHAN_ACCOUNT, OrphanAccountAnomaly
from model.iam import Account, Identity


# Arguments
parser = argparse.ArgumentParser(description='This script observes an orphan account and creates related objects to it if not already present')

parser.add_argument('--account-identifier', help='Identifier of the orphan account', required=True)
parser.add_argument('--account-version', help='Version of the orphan account', required=False)
parser.add_argument('--account-displayname', help='Display name of the orphan account', required=False)
parser.add_argument('--account-owner', help='Owner of the orphan account', required=False)
parser.add_argument('--account-application', help='Application of the orphan account', required=True)

parser.add_argument('--identity-identifier', help='Identifier of an invalid identity regarding the orphan account', required=False)
parser.add_argument('--identity-version', help='Version of an invalid identity regarding the orphan account', required=False)
parser.add_argument('--identity-displayname', help='Display name of an invalid identity regarding the orphan account', required=False)
parser.add_argument('--identity-owner', help='Owner of an invalid identity regarding the orphan account', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + ANOMALY_ORPHAN_ACCOUNT + "-ObservedData.json"
PATH_VULNERABILITY = path + ANOMALY_ORPHAN_ACCOUNT + "-Vulnerability.json"
PATH_COA_ORPHAN_PROCESS = path + ANOMALY_ORPHAN_ACCOUNT + "-CourseOfAction-Process.json"
PATH_COA_ORPHAN_AUTOMATION = path + ANOMALY_ORPHAN_ACCOUNT + "-CourseOfAction-Automation.json"
PATH_COA_ORPHAN_RECERTIFICATION = path + ANOMALY_ORPHAN_ACCOUNT + "-CourseOfAction-Recertification.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + ANOMALY_ORPHAN_ACCOUNT + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_PROCESS = path + ANOMALY_ORPHAN_ACCOUNT + "-Relationship-Vulnerability-CourseOfAction-Process.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_AUTOMATION = path + ANOMALY_ORPHAN_ACCOUNT + "-Relationship-Vulnerability-CourseOfAction-Automation.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_RECERTIFICATION = path + ANOMALY_ORPHAN_ACCOUNT + "-Relationship-Vulnerability-CourseOfAction-Recertification.json"

hasIdentity = args.identity_identifier is not None

# Create Entities
account = Account(
    identifier=args.account_identifier, 
    version=args.account_version, 
    display_name=args.account_displayname, 
    owner=args.account_owner, 
    application=args.account_application
)
if hasIdentity:
    identity = Identity(
        identifier=args.identity_identifier, 
        version=args.identity_version, 
        display_name=args.identity_displayname, 
        owner=args.identity_owner
    )
    anomaly = OrphanAccountAnomaly(
        account=account.id,
        idenity=identity.id,
        allow_custom=True
    )
    relationship_identity_to_anomaly = Relationship(
        relationship_type='refers-to',
        source_ref=identity.id,
        target_ref=anomaly.id, 
        allow_custom=True
    )
else:
    anomaly = OrphanAccountAnomaly(
        account=account.id,
        allow_custom=True
    )
relationship_account_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=account.id,
    target_ref=anomaly.id, 
    allow_custom=True
)



if os.path.isfile(OBSERVED_DATA_PATH):

    # Get observed data from temp
    f = open(OBSERVED_DATA_PATH, "r")
    observed_data = parse(f.read(), allow_custom=True)
    f.close()

    observed_data.object_refs.append(anomaly.id)

    # Update Observation
    with open(OBSERVED_DATA_PATH, "w") as outfile:
        outfile.write(observed_data.serialize(pretty=True))
        outfile.close
    
else:

    # Get reporter from temp
    f = open(path + 'reporter.json', "r")
    reporter = parse(f.read())
    f.close()

    observed_data = ObservedData(
        created_by_ref=reporter.id,
        object_refs=[ anomaly.id ],
        first_observed=STIXdatetime.now(tz=pytz.UTC),
        last_observed=STIXdatetime.now(tz=pytz.UTC),
        number_observed=1, 
        allow_custom=True
    )

    vulnerability = Vulnerability(
        name = "Orphan accounts",
        description = "Accounts may remain usable and have assigned access rights. Especially having administrative access, this can quickly lead to a privilege escalation attack."
    )

    course_of_action_process = CourseOfAction(
        name="Definition of a suffiecient idenity lifecycle",
        description="Especially leaving identities need special consideration: Their accounts need to be terminated to render unusable."
    )

    course_of_action_automation = CourseOfAction(
        name="Automated account cleansing",
        description="Automated provisioning technologies and processes can automatically detect and delete orphan accounts."
    )

    course_of_action_recertification = CourseOfAction(
        name="Regular account recertifications",
        description="Recertifications are a manual and periodical check of the present accounts. Responsible identities, like managers in an enterprise context, can determine wheter an account is orphan."
    )

    relationship_observed_data_to_vulnerability = Relationship(
        relationship_type='observed_data',
        source_ref=observed_data.id,
        target_ref=vulnerability.id
    )

    relationship_coa_process_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_process.id,
        target_ref=vulnerability.id
    )

    relationship_coa_automation_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_automation.id,
        target_ref=vulnerability.id
    )

    relationship_coa_recertification_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_recertification.id,
        target_ref=vulnerability.id
    )

    # Get report from temp
    f = open(path + 'report.json', "r")
    report = parse(f.read())
    f.close()

    report.object_refs.append(vulnerability.id)

    # Save Entities
    with open(OBSERVED_DATA_PATH, "w") as outfile:
        outfile.write(observed_data.serialize(pretty=True))
        outfile.close

    with open(PATH_COA_ORPHAN_PROCESS, "w") as outfile:
        outfile.write(course_of_action_process.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_ORPHAN_AUTOMATION, "w") as outfile:
        outfile.write(course_of_action_automation.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_ORPHAN_RECERTIFICATION, "w") as outfile:
        outfile.write(course_of_action_recertification.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_PROCESS, "w") as outfile:
        outfile.write(relationship_coa_process_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_AUTOMATION, "w") as outfile:
        outfile.write(relationship_coa_automation_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ORPHAN_RECERTIFICATION, "w") as outfile:
        outfile.write(relationship_coa_recertification_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + account.id + ".json", "w") as outfile:
    outfile.write(account.serialize(pretty=True))
    outfile.close
with open(path + anomaly.id + ".json", "w") as outfile:
    outfile.write(anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_account_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_account_to_anomaly.serialize(pretty=True))
    outfile.close

if hasIdentity:
    with open(path + relationship_identity_to_anomaly.id + ".json", "w") as outfile:
        outfile.write(relationship_identity_to_anomaly.serialize(pretty=True))
        outfile.close
    with open(path + identity.id + ".json", "w") as outfile:
        outfile.write(identity.serialize(pretty=True))
        outfile.close