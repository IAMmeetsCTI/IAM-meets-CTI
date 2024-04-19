import argparse, pytz, os, sys
from stix2 import parse, properties
from stix2.v21 import ObservedData, Vulnerability, CourseOfAction, Relationship
from stix2.utils import STIXdatetime

typedir = os.path.dirname(os.path.realpath(__file__))
observedir = os.path.dirname(typedir)
sciptsdir = os.path.dirname(observedir)
parentdir = os.path.dirname(sciptsdir)
sys.path.append(parentdir)

from model.anomalies import ANOMALY_PRIVACY_LEAK, PrivacyLeakAnomaly
from model.iam import Identity


# Arguments
parser = argparse.ArgumentParser(description='This script observes an orphan account and creates related objects to it if not already present.')

parser.add_argument('--identity-identifier', help='Identifier of a identity with leaked attribute values.', required=True)
parser.add_argument('--identity-version', help='Version of a identity with leaked attribute values.', required=False)
parser.add_argument('--identity-displayname', help='Display name of a identity with leaked attribute values.', required=False)
parser.add_argument('--identity-owner', help='Owner of a identity with leaked attribute values.', required=False)

parser.add_argument('--leaked-attributes', help='Denotes the leaked attributes for the affected identity.', required=True, nargs='+')

parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# VARS
path = args.out + "temp/"
OBSERVED_DATA_PATH = path + ANOMALY_PRIVACY_LEAK + "-ObservedData.json"
PATH_VULNERABILITY = path + ANOMALY_PRIVACY_LEAK + "-Vulnerability.json"
PATH_COA_ANONYMIZATION = path + ANOMALY_PRIVACY_LEAK + "-CourseOfAction-Anonymization.json"
PATH_COA_ENCRYPTION = path + ANOMALY_PRIVACY_LEAK + "-CourseOfAction-Encryption.json"
PATH_COA_RECERTIFICATION = path + ANOMALY_PRIVACY_LEAK + "-CourseOfAction-Recertification.json"

PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY = path + ANOMALY_PRIVACY_LEAK + "-Relationship-ObservedData-Vulnerability.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ANONYMIZATION = path + ANOMALY_PRIVACY_LEAK + "-Relationship-Vulnerability-CourseOfAction-Anonymization.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_ENCRYPTION = path + ANOMALY_PRIVACY_LEAK + "-Relationship-Vulnerability-CourseOfAction-Encryption.json"
PATH_RELATIONSHIP_VULNERABILITY_COA_RECERTIFICATION = path + ANOMALY_PRIVACY_LEAK + "-Relationship-Vulnerability-CourseOfAction-Recertification.json"

# Create Entities
identity = Identity(
    identifier=args.identity_identifier, 
    version=args.identity_version, 
    display_name=args.identity_displayname, 
    owner=args.identity_owner
)
anomaly = PrivacyLeakAnomaly(
    affected_identity=identity.id,
    leaked_attributes=args.leaked_attributes,
    allow_custom=True
)
relationship_identity_to_anomaly = Relationship(
    relationship_type='refers-to',
    source_ref=identity.id,
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
        name = "Privacy Leak",
        description = "Privacy-related information can be used by attackers for further attacks (e.g., Spear Phishing Attacks). Leakage of privacy-related information may result in financial or image loss (e.g., GDPR penalties)."
    )
    course_of_action_anonymization = CourseOfAction(
        name="Anonymization of privacy-related information",
        description="Privacy-related information are effectively protected by anonymization techniques (e.g. macro data or perturbative or non-perturbative anonymizaiton of micro data)."
    )
    course_of_action_encryption = CourseOfAction(
        name="Encryption of privacy-related information",
        description="Privacy-related information can be protected by encryption. This approach is especially important for use cases where the private data needs to be retrieved later from an authorized identity."
    )
    course_of_action_recertification = CourseOfAction(
        name="Regualar recertifications",
        description="Due to regular recertifications, excessive access to privacy-related information of an identity can be identified."
    )
    relationship_observed_data_to_vulnerability = Relationship(
        relationship_type='observed_data',
        source_ref=observed_data.id,
        target_ref=vulnerability.id
    )
    relationship_coa_anonymization_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_anonymization.id,
        target_ref=vulnerability.id
    )
    relationship_coa_encryption_to_vulnerability = Relationship(
        relationship_type='course-of-action',
        source_ref=course_of_action_encryption.id,
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

    with open(PATH_COA_ANONYMIZATION, "w") as outfile:
        outfile.write(course_of_action_anonymization.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_ENCRYPTION, "w") as outfile:
        outfile.write(course_of_action_encryption.serialize(pretty=True))
        outfile.close
    with open(PATH_COA_RECERTIFICATION, "w") as outfile:
        outfile.write(course_of_action_recertification.serialize(pretty=True))
        outfile.close

    with open(PATH_VULNERABILITY, "w") as outfile:
        outfile.write(vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_OBSERVED_DATA_VULNERABILITY, "w") as outfile:
        outfile.write(relationship_observed_data_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ANONYMIZATION, "w") as outfile:
        outfile.write(relationship_coa_anonymization_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_ENCRYPTION, "w") as outfile:
        outfile.write(relationship_coa_encryption_to_vulnerability.serialize(pretty=True))
        outfile.close
    with open(PATH_RELATIONSHIP_VULNERABILITY_COA_RECERTIFICATION, "w") as outfile:
        outfile.write(relationship_coa_recertification_to_vulnerability.serialize(pretty=True))
        outfile.close

    with open(path + "report.json", "w") as outfile:
        outfile.write(report.serialize(pretty=True))
        outfile.close

with open(path + identity.id + ".json", "w") as outfile:
    outfile.write(identity.serialize(pretty=True))
    outfile.close
with open(path + anomaly.id + ".json", "w") as outfile:
    outfile.write(anomaly.serialize(pretty=True))
    outfile.close
with open(path + relationship_identity_to_anomaly.id + ".json", "w") as outfile:
    outfile.write(relationship_identity_to_anomaly.serialize(pretty=True))
    outfile.close