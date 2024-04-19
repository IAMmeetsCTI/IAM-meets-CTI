import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.signatures import SIGNATURE_LIVENESS, LivenessSignature
from model.iam import AccessControlPolicy, Identity


# Arguments
parser = argparse.ArgumentParser(description='This script observes the liveness of a access control policy and creates related objects to it if not already present')

parser.add_argument('--policy-identifier', help='Identifier of the access control policy\'s liveness', required=True)
parser.add_argument('--policy-type', help='Type (permission or role) of the access control policy\'s liveness', required=True, choices=['permission','role'])
parser.add_argument('--policy-version', help='Version of the access control policy\'s liveness', required=False)
parser.add_argument('--policy-displayname', help='Display name of the access control policy\'s liveness', required=False)
parser.add_argument('--policy-owner', help='Owner of the access control policy\'s liveness', required=False)
parser.add_argument('--policy-application', help='Application of the access control policy\'s liveness', required=False)

parser.add_argument('--identity-identifier', help='Identifier of a specialist identity', required=True)
parser.add_argument('--identity-version', help='Version of a specialist identity', required=False)
parser.add_argument('--identity-displayname', help='Display name of a specialist identity', required=False)
parser.add_argument('--identity-owner', help='Owner of a specialist identity', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + SIGNATURE_LIVENESS + "-ObservedData.json"
PATH_VULNERABILITY = path + SIGNATURE_LIVENESS + "-Vulnerability.json"
PATH_COA_LIVENESS_CHECKS = path + SIGNATURE_LIVENESS + "-CourseOfAction-Checks.json"
PATH_COA_LIVENESS_DESIGN = path + SIGNATURE_LIVENESS + "-CourseOfAction-Design.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + SIGNATURE_LIVENESS + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_LIVENESS_CHECKS = path + SIGNATURE_LIVENESS + "-Relationship-Vulnerability-CourseOfAction-Checks.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_LIVENESS_DESIGN = path + SIGNATURE_LIVENESS + "-Relationship-Vulnerability-CourseOfAction-Design.json"

# Create Entities
access_control_policy = AccessControlPolicy(
    identifier=args.policy_identifier, 
    acp_type=args.policy_type, 
    version=args.policy_version, 
    display_name=args.policy_displayname, 
    owner=args.policy_owner, 
    application=args.policy_application
)
identity = Identity(
    identifier=args.identity_identifier, 
    version=args.identity_version, 
    display_name=args.identity_displayname, 
    owner=args.identity_owner
)
signature = LivenessSignature(
    access_control_policy=access_control_policy.id, 
    identity=identity.id,
    allow_custom=True
)
relationship_access_control_policy_to_signature = Relationship(
    relationship_type='refers-to',
    source_ref=access_control_policy.id,
    target_ref=signature.id, 
    allow_custom=True
)
relationship_identity_to_signature = Relationship(
    relationship_type='refers-to',
    source_ref=identity.id,
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
        name = "Access control policy liveness (specialist entitlement)",
        description = "Access control policies are only assigned to one identity in the entire domain. After leave or move of specialist identity the access control policy can not be used anymore (until it is manually assigned to further identities)."
    )
    course_of_action_checks = CourseOfAction(
        name="Automatically check access control policies for liveness",
        description="Automated checks for the liveness of access control policies establish a vision for specialsts which hamper smooth operations on move or leave."
    )
    course_of_action_design = CourseOfAction(
        name="Redesign assignments for access control policies",
        description="The access control policy might need more assignments to identities. E.g. a realization of access control policies as roles add specialist access control polcies to a broader spectrum of identities."
    )
    relationship_observed_data_to_vulnerability = Relationship(
        relationship_type='observed_data',
        source_ref=observed_data.id,
        target_ref=vulnerability.id
    )
    relationship_coa_checks_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_checks.id,
        target_ref=vulnerability.id
    )
    relationship_coa_design_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_design.id,
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

    with open(PATH_COA_LIVENESS_CHECKS, "w") as outfile:
        outfile.write(course_of_action_checks.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_LIVENESS_DESIGN, "w") as outfile:
        outfile.write(course_of_action_design.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_LIVENESS_CHECKS, "w") as outfile:
        outfile.write(relationship_coa_checks_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_LIVENESS_DESIGN, "w") as outfile:
        outfile.write(relationship_coa_design_to_vulnerability.serialize(pretty=True))
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
with open(path + signature.id + ".json", "w") as outfile:
    outfile.write(signature.serialize(pretty=True))
    outfile.close
with open(path + relationship_access_control_policy_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_access_control_policy_to_signature.serialize(pretty=True))
    outfile.close
with open(path + relationship_identity_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_identity_to_signature.serialize(pretty=True))
    outfile.close