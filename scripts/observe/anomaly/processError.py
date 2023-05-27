import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.anomalies import ANOMALY_PROCESS_ERROR, ProcessErrorAnomaly
from model.iam import AccessControlPolicy, Identity, Account, Process


# Arguments
parser = argparse.ArgumentParser(description='This script observes a process error of an IAM entity (account, identity, permission, role).')

parser.add_argument('--process-identifier', help='Identifier of an process', required=True)
parser.add_argument('--process-displayname', help='Display name of an process', required=False)

parser.add_argument('--type', help='Type (identity, account, permission, or role) of an entity', required=True, choices=['account','identity','permission','role'])

parser.add_argument('--policy-identifier', help='Identifier of an access control policy', required=False)
parser.add_argument('--policy-version', help='Version of an access control policy', required=False)
parser.add_argument('--policy-displayname', help='Display name of an access control policy', required=False)
parser.add_argument('--policy-owner', help='Owner of an access control policy', required=False)
parser.add_argument('--policy-application', help='Application of an access control policy', required=False)

parser.add_argument('--identity-identifier', help='Identifier of a identity', required=False)
parser.add_argument('--identity-version', help='Version of a identity', required=False)
parser.add_argument('--identity-displayname', help='Display name of a identity', required=False)
parser.add_argument('--identity-owner', help='Owner of a identity', required=False)

parser.add_argument('--account-identifier', help='Identifier of an account', required=False)
parser.add_argument('--account-version', help='Version of an account', required=False)
parser.add_argument('--account-displayname', help='Display name of an account', required=False)
parser.add_argument('--account-owner', help='Owner of an account', required=False)
parser.add_argument('--account-application', help='Application of an account', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + ANOMALY_PROCESS_ERROR + "-ObservedData.json"
PATH_VULNERABILITY = path + ANOMALY_PROCESS_ERROR + "-Vulnerability.json"
PATH_COA_AUTOMATION = path + ANOMALY_PROCESS_ERROR + "-CourseOfAction-Automation.json"
PATH_COA_INTEGRATION = path + ANOMALY_PROCESS_ERROR + "-CourseOfAction-Integration.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + ANOMALY_PROCESS_ERROR + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_AUTOMATION = path + ANOMALY_PROCESS_ERROR + "-Relationship-Vulnerability-CourseOfAction-Automation.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_INTEGRATION = path + ANOMALY_PROCESS_ERROR + "-Relationship-Vulnerability-CourseOfAction-Integration.json"

# Create Entities
process = Process(
    identifier=args.process_identifier, 
    display_name=args.process_displayname
)
if args.type == 'role' or args.type == 'permission':
    if args.policy_identifier is None:
        raise ValueError('Access control policy identifier is required on type role or permission.')
    entity = AccessControlPolicy(
        identifier=args.policy_identifier, 
        acp_type=args.type, 
        version=args.policy_version, 
        display_name=args.policy_displayname, 
        owner=args.policy_owner, 
        application=args.policy_application
    )
elif args.type == 'account':
    if args.account_identifier is None:
        raise ValueError('Account identifier is required on type account.')
    entity = Account(
        identifier=args.account_identifier, 
        version=args.account_version, 
        display_name=args.account_displayname, 
        owner=args.account_owner, 
        application=args.account_application
    )
elif args.type == 'identity':
    if args.identity_identifier is None:
        raise ValueError('Identity identifier is required on type identity.')
    entity = Identity(
        identifier=args.identity_identifier, 
        version=args.identity_version, 
        display_name=args.identity_displayname, 
        owner=args.identity_owner
    )
else:
    raise ValueError('We did not recognize the type for the missing recertification.')

anomaly = ProcessErrorAnomaly(
    entity=entity.id, 
    process=process.id,
    allow_custom=True
)
relationship_entity_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=entity.id,
    target_ref=anomaly.id, 
    allow_custom=True
)
relationship_process_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=process.id,
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
        name = "Process bypass",
        description = "Attackers may want to bypass defined processes in order to gain elevated access without a mandatory approval."
    )
    course_of_action_automation = CourseOfAction(
        name="Automation of processes",
        description="Automated processes tend to be less error-prone. E.g. a self-service process can streamline authorization requests which eases and accelerate their processing."
    )
    course_of_action_integration = CourseOfAction(
        name="Process integration",
        description="Processes can be integrated in centralized IAM workflows. This gives vision and more consistency for IAM processes. Process Errors can be identified quicker and more precise."
    )
    relationship_observed_data_to_vulnerability = Relationship(
        relationship_type='observed_data',
        source_ref=observed_data.id,
        target_ref=vulnerability.id
    )
    relationship_coa_automation_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_automation.id,
        target_ref=vulnerability.id
    )
    relationship_coa_integration_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_integration.id,
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

    with open(PATH_COA_AUTOMATION, "w") as outfile:
        outfile.write(course_of_action_automation.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_INTEGRATION, "w") as outfile:
        outfile.write(course_of_action_integration.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_AUTOMATION, "w") as outfile:
        outfile.write(relationship_coa_automation_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_INTEGRATION, "w") as outfile:
        outfile.write(relationship_coa_integration_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + entity.id + ".json", "w") as outfile:
    outfile.write(entity.serialize(pretty=True))
    outfile.close
with open(path + process.id + ".json", "w") as outfile:
    outfile.write(process.serialize(pretty=True))
    outfile.close
with open(path + anomaly.id + ".json", "w") as outfile:
    outfile.write(anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_entity_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_entity_to_anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_process_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_process_to_anomaly.serialize(pretty=True))
    outfile.close