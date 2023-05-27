import argparse, pytz, os, sys
from stix2 import parse
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.signatures import SIGNATURE_SOD_VIOLATION, SoDViolationSignature
from model.iam import AccessControlPolicy, Identity


# Arguments
parser = argparse.ArgumentParser(description='This script observes a Segegration of Duties (SoD) violation and creates related objects to it if not already present')

parser.add_argument('--policy-1-identifier', help='Identifier of the first access control policy of the violation', required=True)
parser.add_argument('--policy-1-type', help='Type (permission or role) of the first access control policy of the violation', required=True, choices=['permission','role'])
parser.add_argument('--policy-1-version', help='Version of the first access control policy of the violation', required=False)
parser.add_argument('--policy-1-displayname', help='Display name of the first access control policy of the violation', required=False)
parser.add_argument('--policy-1-owner', help='Owner of the first access control policy of the violation', required=False)
parser.add_argument('--policy-1-application', help='Application of the first access control policy of the violation', required=False)

parser.add_argument('--policy-2-identifier', help='Identifier of the second access control policy violation', required=True)
parser.add_argument('--policy-2-type', help='Type (permission or role) of the second access control policy violation', required=True, choices=['permission','role'])
parser.add_argument('--policy-2-version', help='Version of the second access control policy violation', required=False)
parser.add_argument('--policy-2-displayname', help='Display name of the second access control policy violation', required=False)
parser.add_argument('--policy-2-owner', help='Owner of the second access control policy violation', required=False)
parser.add_argument('--policy-2-application', help='Application of the second access control policy violation', required=False)

parser.add_argument('--identity-identifier', help='Identifier of the identity causing the SoD violation', required=True)
parser.add_argument('--identity-version', help='Version of the identity causing the SoD violation', required=False)
parser.add_argument('--identity-displayname', help='Display name of the identity causing the SoD violation', required=False)
parser.add_argument('--identity-owner', help='Owner of the identity causing the SoD violation', required=False)

parser.add_argument('--sod-rule', help='A textual representation of the SoD rule', required=False)

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + SIGNATURE_SOD_VIOLATION + "-ObservedData.json"
PATH_VULNERABILITY = path + SIGNATURE_SOD_VIOLATION + "-Vulnerability.json"
PATH_COA_CHECKS = path + SIGNATURE_SOD_VIOLATION + "-CourseOfAction-Checks.json"
PATH_COA_DESIGN = path + SIGNATURE_SOD_VIOLATION + "-CourseOfAction-Design.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + SIGNATURE_SOD_VIOLATION + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_CHECKS = path + SIGNATURE_SOD_VIOLATION + "-Relationship-Vulnerability-CourseOfAction-Checks.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_DESIGN = path + SIGNATURE_SOD_VIOLATION + "-Relationship-Vulnerability-CourseOfAction-Design.json"

# Create Entities
access_control_policy_1 = AccessControlPolicy(
    identifier=args.policy_1_identifier, 
    acp_type=args.policy_1_type, 
    version=args.policy_1_version, 
    display_name=args.policy_1_displayname, 
    owner=args.policy_1_owner, 
    application=args.policy_1_application
)
access_control_policy_2 = AccessControlPolicy(
    identifier=args.policy_2_identifier, 
    acp_type=args.policy_2_type, 
    version=args.policy_2_version, 
    display_name=args.policy_2_displayname, 
    owner=args.policy_2_owner, 
    application=args.policy_2_application
)
identity = Identity(
    identifier=args.identity_identifier, 
    version=args.identity_version, 
    display_name=args.identity_displayname, 
    owner=args.identity_owner
)
signature = SoDViolationSignature(
    access_control_policies=[access_control_policy_1.id, access_control_policy_2.id], 
    identity=identity.id,
    sod_rule=args.sod_rule,
    allow_custom=True
)
relationship_access_control_policy_1_to_signature = Relationship(
    relationship_type='refers-to',
    source_ref=access_control_policy_1.id,
    target_ref=signature.id, 
    allow_custom=True
)
relationship_access_control_policy_2_to_signature = Relationship(
    relationship_type='refers-to',
    source_ref=access_control_policy_2.id,
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
        name = "Toxic combination of authorizations",
        description = "Identities may have toxic permission combinations assigned. Using a combination of two or more permissions can lead to potentially dangerous actions (e.g., creation and approval of invoice). SoD violations can lead to unwanted outflow of information or access to resources."
    )
    course_of_action_checks = CourseOfAction(
        name="Automated SoD checks",
        description="An automated check (e.g. on every new access control policy assignment or on a nightly basis) provides vision for SoD violation. Effective measures are prevent or revoke the assignment"
    )
    course_of_action_design = CourseOfAction(
        name="(Re-)design of SoD policies",
        description="Issues with SoD violations might indicate a problem with their design. Frequent violations thus might be redesigned (e.g. a basic role might not need a toxic access control policy). Additionally, an access control policy might be falsely flagged as toxic, making a reevaluation relevant."
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

    with open(PATH_COA_CHECKS, "w") as outfile:
        outfile.write(course_of_action_checks.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_DESIGN, "w") as outfile:
        outfile.write(course_of_action_design.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_CHECKS, "w") as outfile:
        outfile.write(relationship_coa_checks_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_DESIGN, "w") as outfile:
        outfile.write(relationship_coa_design_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + access_control_policy_1.id + ".json", "w") as outfile:
    outfile.write(access_control_policy_1.serialize(pretty=True))
    outfile.close
with open(path + access_control_policy_2.id + ".json", "w") as outfile:
    outfile.write(access_control_policy_2.serialize(pretty=True))
    outfile.close
with open(path + identity.id + ".json", "w") as outfile:
    outfile.write(identity.serialize(pretty=True))
    outfile.close
with open(path + signature.id + ".json", "w") as outfile:
    outfile.write(signature.serialize(pretty=True))
    outfile.close
with open(path + relationship_access_control_policy_1_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_access_control_policy_1_to_signature.serialize(pretty=True))
    outfile.close
with open(path + relationship_access_control_policy_2_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_access_control_policy_2_to_signature.serialize(pretty=True))
    outfile.close
with open(path + relationship_identity_to_signature.id + ".json", "w") as outfile:
    outfile.write(relationship_identity_to_signature.serialize(pretty=True))
    outfile.close