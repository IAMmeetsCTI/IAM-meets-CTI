from stix2 import properties 
from stix2.v21 import CustomObservable
from model.iam import AccessControlPolicy, Identity, Account

SIGNATURE_SOD_VIOLATION='x-observable-signature-sod-violation'
SIGNATURE_DEAD_ACP='x-observable-signature-dead-acp'
SIGNATURE_LIVENESS='x-observable-signature-liveness'
SIGNATURE_MISSING_RECERTIFICATION='x-observable-signature-missing-recertification'

@CustomObservable(SIGNATURE_SOD_VIOLATION, [
    ('identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=True)),
    ('sod_rule', properties.StringProperty(required=False)),
    ('access_control_policies', properties.ListProperty(required=True, contained=properties.ObjectReferenceProperty(valid_types=[AccessControlPolicy], required=True)))
])
class SoDViolationSignature(object):
    pass

@CustomObservable(SIGNATURE_DEAD_ACP, [
    ('access_control_policy', properties.ObjectReferenceProperty(valid_types=[AccessControlPolicy], required=True))
])
class DeadACPSignature(object):
    pass

@CustomObservable(SIGNATURE_LIVENESS, [
    ('access_control_policy', properties.ObjectReferenceProperty(valid_types=[AccessControlPolicy], required=True)),
    ('identity', properties.ObjectReferenceProperty(valid_types=[Identity], required=True))
])
class LivenessSignature(object):
    pass

@CustomObservable(SIGNATURE_MISSING_RECERTIFICATION, [
    ('entity', properties.ObjectReferenceProperty(valid_types=[Account,Identity,AccessControlPolicy], required=True))
])
class MissingRecertificationSignature(object):
    pass
