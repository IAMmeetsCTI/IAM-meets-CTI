import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.anomalies import ANOMALY_EXCESSIVE_ACCESS, ExcessiveAccessAnomaly
from model.iam import Identity, AccessControlPolicy


# Arguments
parser = argparse.ArgumentParser(description='This script observes excessive access of an identity and creates related objects to it if not already present')

parser.add_argument('--identity-identifier', help='Identifier of an identity with excessive access', required=True)
parser.add_argument('--identity-version', help='Version of an identity with excessive access', required=False)
parser.add_argument('--identity-displayname', help='Display name of an identity with excessive access', required=False)
parser.add_argument('--identity-owner', help='Owner of an identity with excessive access', required=False)

parser.add_argument('--policy-identifier', help='Identifier of the excessive access control policy', required=True)
parser.add_argument('--policy-type', help='Type (permission or role) of the excessive access control policy', required=True, choices=['permission','role'])
parser.add_argument('--policy-version', help='Version of the excessive access control policy', required=False)
parser.add_argument('--policy-displayname', help='Display name of the excessive access control policy', required=False)
parser.add_argument('--policy-owner', help='Owner of the excessive access control policy', required=False)
parser.add_argument('--policy-application', help='Application of the excessive access control policy', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + ANOMALY_EXCESSIVE_ACCESS + "-ObservedData.json"
PATH_VULNERABILITY = path + ANOMALY_EXCESSIVE_ACCESS + "-Vulnerability.json"
PATH_COA_PROCESS = path + ANOMALY_EXCESSIVE_ACCESS + "-CourseOfAction-Process.json"
PATH_COA_AUTOMATION = path + ANOMALY_EXCESSIVE_ACCESS + "-CourseOfAction-Automation.json"
PATH_COA_RECERTIFICATION = path + ANOMALY_EXCESSIVE_ACCESS + "-CourseOfAction-Recertification.json"
PATH_COA_ATTRIBUTEBASED = path + ANOMALY_EXCESSIVE_ACCESS + "-CourseOfAction-AttributeBased.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + ANOMALY_EXCESSIVE_ACCESS + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_PROCESS = path + ANOMALY_EXCESSIVE_ACCESS + "-Relationship-Vulnerability-CourseOfAction-Process.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_AUTOMATION = path + ANOMALY_EXCESSIVE_ACCESS + "-Relationship-Vulnerability-CourseOfAction-Automation.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_RECERTIFICATION = path + ANOMALY_EXCESSIVE_ACCESS + "-Relationship-Vulnerability-CourseOfAction-Recertification.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ATTRIBUTEBASED = path + ANOMALY_EXCESSIVE_ACCESS + "-Relationship-Vulnerability-CourseOfAction-AttributeBased.json"


hasIdentity = args.identity_identifier is not None

# Create Entities
identity = Identity(
    identifier=args.identity_identifier, 
    version=args.identity_version, 
    display_name=args.identity_displayname, 
    owner=args.identity_owner
)
access_control_policy = AccessControlPolicy(
    identifier=args.policy_identifier, 
    acp_type=args.policy_type, 
    version=args.policy_version, 
    display_name=args.policy_displayname, 
    owner=args.policy_owner, 
    application=args.policy_application
)
anomaly = ExcessiveAccessAnomaly(
    identity=identity.id,
    access_control_policy=access_control_policy.id,
    allow_custom=True
)
relationship_identity_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=identity.id,
    target_ref=anomaly.id, 
    allow_custom=True
)
relationship_access_control_policy_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=access_control_policy.id,
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
        name = "Excessive access",
        description = "Identities may keep critical access control policies which can be used for potential attacks. Especially having administrative access control policies, this can quickly lead to a privilege escalation attack."
    )
    course_of_action_process = CourseOfAction(
        name="Definition of sufficient mover processes",
        description="Mover processes should manage granting required and revoking obsolete access when an identity is moving towards a new position. Revoking obsolete access thus can help to mitigate excessive access."
    )
    course_of_action_automation = CourseOfAction(
        name="Automation of account cleansing",
        description="Especially orphan or outdated accounts might still be able to access sensible information or functions. Deprovision of these thus effectively terminates excessive access within the managed systems."
    )
    course_of_action_recertification = CourseOfAction(
        name="Regular recertifications of accounts",
        description="Responsible identities for IAM entities (like roles, permissions, accounts and identities), should periodically check their entities. This mitigates risks of outdated entities or their assignments. E.g. idenities with excessive access should at least be noticed during recertifications."
    )
    course_of_action_attribute_based = CourseOfAction(
        name="Automated access control policy assignment or attribute-based assignment",
        description="An assignment of access control policies based on attribtues utilizes the attributes of identities and access control policies for assignments. This thus creates a more dynamic and automated assignment of access control policies. "
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
    relationship_coa_attribute_based_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_attribute_based.id,
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

    with open(PATH_COA_PROCESS, "w") as outfile:
        outfile.write(course_of_action_process.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_AUTOMATION, "w") as outfile:
        outfile.write(course_of_action_automation.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_RECERTIFICATION, "w") as outfile:
        outfile.write(course_of_action_recertification.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_ATTRIBUTEBASED, "w") as outfile:
        outfile.write(course_of_action_attribute_based.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_PROCESS, "w") as outfile:
        outfile.write(relationship_coa_process_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_AUTOMATION, "w") as outfile:
        outfile.write(relationship_coa_automation_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_RECERTIFICATION, "w") as outfile:
        outfile.write(relationship_coa_recertification_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ATTRIBUTEBASED, "w") as outfile:
        outfile.write(relationship_coa_attribute_based_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + access_control_policy.id + ".json", "w") as outfile:
    outfile.write(access_control_policy.serialize(pretty=True))
    outfile.close
with open(path + identity.id + ".json", "w") as outfile:
    outfile.write(identity.serialize(pretty=True))
    outfile.close
with open(path + anomaly.id + ".json", "w") as outfile:
    outfile.write(anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_access_control_policy_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_access_control_policy_to_anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_identity_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_identity_to_anomaly.serialize(pretty=True))
    outfile.close


