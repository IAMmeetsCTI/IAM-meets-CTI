import argparse, os
from stix2 import parse
from stix2.v21 import Bundle

# Arguments
parser = argparse.ArgumentParser(description='This script finalizes the report and puts the result in the reports dir')
parser.add_argument('--out', help="Path for the output", required=False)
args = parser.parse_args()

# Read STIX objects to Bundle
path_temp = args.out + "temp/"
stix_objects = []
for file in os.listdir(path_temp):
    if file.endswith('.json'):
        f = open(path_temp+file, "r")
        stix_objects.append(parse(f.read(), allow_custom=True))
        f.close()
bundle = Bundle(objects=stix_objects, allow_custom=True)

# Prepare Reports Dirs
path_reports = args.out + "reports/"
isExist = os.path.exists(path_reports)
if not isExist:
   os.makedirs(path_reports)

# Save Bundle
with open(path_reports + bundle.id + ".json", "w") as outfile:
    outfile.write(bundle.serialize(pretty=True))
    outfile.close

# Clear Temp
filelist = [ f for f in os.listdir(path_temp) if f.endswith(".json") ]
for f in filelist:
    os.remove(os.path.join(path_temp, f))