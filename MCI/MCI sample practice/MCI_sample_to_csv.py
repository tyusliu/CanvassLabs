import xml.etree.ElementTree as ET

tree = ET.parse('MCI_sample.xml')
root = tree.getroot()
print('-----id-----')
for child in root:
    print(child.attrib)
print(root[1][0][0].text)