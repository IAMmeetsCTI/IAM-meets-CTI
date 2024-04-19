import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.signatures import SIGNATURE_DEAD_ACP, DeadACPSignature
from model.iam import AccessControlPolicy


# Arguments
parser = argparse.ArgumentParser(description='This script observes a dead acp and creates related objects to it if not already present')

parser.add_argument('--identifier', help='Identifier of the dead access control policy', required=True)
parser.add_argument('--type', help='Type (permission or role) of the dead access control policy', required=True, choices=['permission','role'])

parser.add_argument('--version', help='Version of the dead access control policy', required=False)
parser.add_argument('--displayname', help='Display name of the dead access control policy', required=False)
parser.add_argument('--owner', help='Owner of the dead access control policy', required=False)
parser.add_argument('--application', help='Application of the dead access control policy', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + SIGNATURE_DEAD_ACP + "-ObservedData.json"
PATH_VULNERABILITY = path + SIGNATURE_DEAD_ACP + "-Vulnerability.json"
PATH_COA_DEAD_ACP_VISION = path + SIGNATURE_DEAD_ACP + "-CourseOfAction-Vision.json"
PATH_COA_DEAD_ACP_DELETE = path + SIGNATURE_DEAD_ACP + "-CourseOfAction-Delete.json"
PATH_COA_DEAD_ACP_OWNERSHIP = path + SIGNATURE_DEAD_ACP + "-CourseOfAction-Ownership.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + SIGNATURE_DEAD_ACP + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_VISION = path + SIGNATURE_DEAD_ACP + "-Relationship-Vulnerability-CourseOfAction-Vision.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_DELETE = path + SIGNATURE_DEAD_ACP + "-Relationship-Vulnerability-CourseOfAction-Delete.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_OWNERSHIP = path + SIGNATURE_DEAD_ACP + "-Relationship-Vulnerability-CourseOfAction-Ownership.json"

# Create Entities
access_control_policy = AccessControlPolicy(
    identifier=args.identifier, 
    acp_type=args.type, 
    version=args.version, 
    display_name=args.displayname, 
    owner=args.owner, 
    application=args.application)

signature = DeadACPSignature(
    access_control_policy=access_control_policy.id, allow_custom=True)

relationship_access_control_policy_to_signature = Relationship(
    relationship_type='refers-to',
    source_ref=access_control_policy.id,
    target_ref=signature.id, 
    allow_custom=True
)

if os.path.isfile(OBSERVED_DATA_PATH):

    # Get observed data from temp
    f = open(OBSERVED_DATA_PATH, "r")
    observed_data = parse(f.read(), allow_custom=True)
    f.close()

    observed_data.object_refs.append(signature.id)

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
        object_refs=[ signature.id ],
        first_observed=STIXdatetime.now(tz=pytz.UTC),
        last_observed=STIXdatetime.now(tz=pytz.UTC),
        number_observed=1, 
        allow_custom=True
    )

    vulnerability = Vulnerability(
        name = "Dead access control policies",
        description = "Access control policies, which are still in existence can be used by an attacker to gain privileged access rights. As long as entitlements are not technically deleted they can still be used at any time."
    )

    course_of_action_vision = CourseOfAction(
        name="Get vision for access control policies",
        description="Apply automated checks for dead access control policies for reporting."
    )

    course_of_action_delete = CourseOfAction(
        name="Delete dead access control policies",
        description="Establish a structured process to technically delete dead access control policies."
    )

    course_of_action_ownership = CourseOfAction(
        name="Assign owners for access control policies",
        description="Definition of sufficient owner structure to identify dead access control policies."
    )

    relationship_observed_data_to_vulnerability = Relationship(
        relationship_type='observed_data',
        source_ref=observed_data.id,
        target_ref=vulnerability.id
    )

    relationship_coa_vision_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_vision.id,
        target_ref=vulnerability.id
    )

    relationship_coa_delete_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_delete.id,
        target_ref=vulnerability.id
    )

    relationship_coa_ownership_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_ownership.id,
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

    with open(PATH_COA_DEAD_ACP_VISION, "w") as outfile:
        outfile.write(course_of_action_vision.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_DEAD_ACP_DELETE, "w") as outfile:
        outfile.write(course_of_action_delete.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_DEAD_ACP_OWNERSHIP, "w") as outfile:
        outfile.write(course_of_action_ownership.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_VISION, "w") as outfile:
        outfile.write(relationship_coa_vision_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_DELETE, "w") as outfile:
        outfile.write(relationship_coa_delete_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_DEAD_ACP_OWNERSHIP, "w") as outfile:
        outfile.write(relationship_coa_ownership_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + access_control_policy.id + ".json", "w") as outfile:
    outfile.write(access_control_policy.serialize(pretty=True))
    outfile.close

with open(path + signature.id + ".json", "w") as outfile:
    outfile.write(signature.serialize(pretty=True))
    outfile.close

with open(path + relationship_access_control_policy_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_access_control_policy_to_signature.serialize(pretty=True))
    outfile.close
