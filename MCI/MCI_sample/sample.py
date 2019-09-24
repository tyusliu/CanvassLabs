import xml.etree.ElementTree as ET
import csv
import json
import re
#GOAL: print out all of the maven names that have matches to the CPE name or CVE desc.
def count_words(how_many_words_in_this_string):
    """Counts words in the given string"""
    if isinstance(how_many_words_in_this_string, str):
        lengthList = how_many_words_in_this_string.split()
        return len(lengthList)
    else:
        raise ValueError("Input must be a String")

def add_1_to_dict_if_exist(a_dict, key):
    """Adds 1 to any dictionary key if it exists."""
    if key not in a_dict.keys():
        a_dict[key] = 1
    elif key in a_dict.keys():
        a_dict[key] = a_dict[key] + 1

def make_list_of_values_given_dict(a_dict, a_set):
    """Makes a list of values from the unique keys in a dict."""
    s = []
    for elts in a_set:
        s.append(a_dict[elts])
    return s

def make_set_of_keys_given_dict(a_dict):
    """Makes a set of the unique keys in a dict."""
    s = set(keys for keys in a_dict.keys())
    return s

def add_single_year_dict_to_corpus_dict(all_year_dict, single_year_dict, filename):
    """Adds the single year dict into the structure for the corpus dict."""
    all_year_dict[filename] = single_year_dict

def make_dict_for_all_desc_words_across_single_year(nvdcve_dict):
    """Makes a dictionary of desc words given json from a single year."""
    single_year_dict = {}
    description_string = ''
    for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
        single_year_dict[cve_items_index] = {}
        cve_items = nvdcve_dict['CVE_Items'][cve_items_index]
        cve_cve_category = cve_items['cve']
        cve_description = cve_cve_category['description']
        description_string = cve_description['description_data'][0]['value'].lower()
        cve_item_description_words_list = re.sub("[^\w]", " ", description_string).split()
        for current_word in cve_item_description_words_list:
            if current_word not in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = 1
            elif current_word in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = single_year_dict[cve_items_index][current_word] + 1
    return single_year_dict

def generate_ngrams_from_sentence(s, n):
    # Convert to lowercases
    s = s.lower()
    # Remove all none alphanumeric characters with spaces
    #s = re.sub(r'[^a-zA-Z0-9\s]', '', s)
    # Break sentence in the token, remove empty tokens
    tokens = [token for token in s.split(" ") if token != ""]
    # Use the zip function to help us generate n-grams
    # Concatentate the tokens into ngrams and return
    ngrams = zip(*[tokens[i:] for i in range(n)])
    ngram_list = [" ".join(ngram) for ngram in ngrams]
    return ngram_list

def generate_ngram_dict_across_single_year(n):
    """Makes a ngram dictionary of desc words from a single json year."""
    single_year_dict = {}
    description_string = ''
    for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
        single_year_dict[cve_items_index] = {}
        cve_items = nvdcve_dict['CVE_Items'][cve_items_index]
        cve_cve_category = cve_items['cve']
        cve_description = cve_cve_category['description']
        description_string = cve_description['description_data'][0]['value'].lower()
        cve_item_description_ngram_list = generate_ngrams_from_sentence(description_string, n)
        for current_word in cve_item_description_ngram_list:
            if current_word not in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = 1
            elif current_word in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = single_year_dict[cve_items_index][current_word] + 1
    return single_year_dict

tree = ET.parse('MCI_sample.xml')
root = tree.getroot()
doc = root[1]
names_dict = {}
for docs in root.iter('doc'):
    for fields in docs.iter('field'):
        if fields.attrib['name'] == 'n':
            #probably do somehting here to get the maven ID
            names_dict[fields[0].text] = 0

cve_json_filenames=['nvdcve-1.0-2019.json']
single_year_dict = {}
all_year_dict = {}
two_ngram_dict = {}
three_ngram_dict = {}
four_ngram_dict = {}
five_ngram_dict = {}
all_year_2gram_dict = {}
all_year_3gram_dict = {}
all_year_4gram_dict = {}
all_year_5gram_dict = {}
#CPE
cpe_product_name = {}
for files in cve_json_filenames:
    print(files)
    with open(files, 'r', encoding="utf8") as f:
        nvdcve_dict = json.load(f)
    single_year_dict = make_dict_for_all_desc_words_across_single_year(nvdcve_dict)
    add_single_year_dict_to_corpus_dict(all_year_dict, single_year_dict, files)
    for n in range(2, 6):
        if n == 2:
            two_ngram_dict = generate_ngram_dict_across_single_year(n)
            add_single_year_dict_to_corpus_dict(all_year_2gram_dict, two_ngram_dict, files)
        elif n == 3:
            three_ngram_dict = generate_ngram_dict_across_single_year(n)
            add_single_year_dict_to_corpus_dict(all_year_3gram_dict, three_ngram_dict, files)
        elif n == 4:
            four_ngram_dict = generate_ngram_dict_across_single_year(n)
            add_single_year_dict_to_corpus_dict(all_year_4gram_dict, four_ngram_dict, files)
        elif n == 5:
            five_ngram_dict = generate_ngram_dict_across_single_year(n)
            add_single_year_dict_to_corpus_dict(all_year_5gram_dict, five_ngram_dict, files)
    #Do the CPE now
    for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
        items = nvdcve_dict['CVE_Items'][cve_items_index]
        for node_index in range(len(items['configurations']['nodes'])):
            nodes = items['configurations']['nodes'][node_index]
            if 'children' in nodes:
                for children_index in range(len(nodes['children'])):
                    children = nodes['children'][children_index]
                    try:
                        for cpe_match_index in range(len(children['cpe_match'])):
                            cpe_matches = children['cpe_match'][cpe_match_index]
                            cpe_parsed_list = cpe_matches['cpe23Uri'].split(':')
                            add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
                    except:
                        #pdb.set_trace()
                        print('----------KeyError Occurred----------')
            else:
                try:
                    for cpe_match_index in range(len(nodes['cpe_match'])):
                        cpe_matches = nodes['cpe_match'][cpe_match_index]
                        cpe_parsed_list = cpe_matches['cpe23Uri'].split(':')
                        add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
                except:
                    #pdb.set_trace()
                    print('----------KeyError Occurred----------')
        cpe_product_name_set_keys = make_set_of_keys_given_dict(cpe_product_name)
        cpe_product_name_set_values = make_list_of_values_given_dict(cpe_product_name, cpe_product_name_set_keys)
#separate pns by spaces
cpe_spaced_list = []
for pns in cpe_product_name_set_keys:
    cpe_spaced_list.append(pns.replace('_', ' '))

#check if there is a match and add to matched_names_dict
matched_names_dict = {}
for all_names in names_dict.keys():
    for all_pns in cpe_spaced_list:
        if all_names == all_pns:
            matched_names_dict[all_names] = 0
            print(all_names)

with open('MCI-CPE_name_check.csv', mode='w') as csv_file:
    fieldnames = ['MCI_Name']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    for names in matched_names_dict.keys():
        writer.writerow({'MCI_Name': names})

