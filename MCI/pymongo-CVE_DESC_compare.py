import xml.etree.ElementTree as ET
import csv
import json
import re
import pymongo
from pymongo import MongoClient
client = MongoClient()
db = client.vulnerabilities
collection = db.mci

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
    indexx_set = set()
    for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
        single_year_dict[cve_items_index] = {}
        cve_items = nvdcve_dict['CVE_Items'][cve_items_index]
        cve_cve_category = cve_items['cve']
        cve_description = cve_cve_category['description']
        description_string = cve_description['description_data'][0]['value'].lower()
        cve_item_description_words_list = re.sub(r"[^\w]", " ", description_string).split()
        for current_word in cve_item_description_words_list:
            if current_word not in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = indexx_set.add(cve_items_index)
            elif current_word in single_year_dict[cve_items_index].keys():
                single_year_dict[cve_items_index][current_word] = single_year_dict[cve_items_index][current_word] + 1
    return single_year_dict

def generate_ngrams_from_sentence(s, n):
    # Convert to lowercases
    s = s.lower()
    # Remove all non alphanumeric characters with spaces
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
    #index_set = set()
    for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
        #index_set.clear()
        cve_ID = nvdcve_dict['CVE_Items'][cve_items_index]['cve']['CVE_data_meta']['ID']
        cve_items = nvdcve_dict['CVE_Items'][cve_items_index]
        cve_cve_category = cve_items['cve']
        cve_description = cve_cve_category['description']
        description_string = cve_description['description_data'][0]['value'].lower()
        cve_item_description_ngram_list = generate_ngrams_from_sentence(description_string, n)
        for current_word in cve_item_description_ngram_list:
            #index_set.add(cve_ID)
            if current_word not in single_year_dict:
                single_year_dict[current_word] = cve_ID
                last_CVE_ID = cve_ID
            elif current_word in single_year_dict:
                if last_CVE_ID != cve_ID:
                    single_year_dict[current_word] = single_year_dict[current_word] + ', ' + cve_ID
    return single_year_dict

def merge_two_dicts(x, y):
    """Merges two dictionaries and returns the result."""
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

distinct_maven_names = collection.distinct('artifact_u')

cve_json_filenames=['nvdcve-1.0-2019.json', 'nvdcve-1.0-2018.json', 
                    'nvdcve-1.0-2017.json', 'nvdcve-1.0-2016.json', 
                    'nvdcve-1.0-2015.json', 'nvdcve-1.0-2014.json', 
                    'nvdcve-1.0-2013.json', 'nvdcve-1.0-2012.json', 
                    'nvdcve-1.0-2011.json', 'nvdcve-1.0-2010.json', 
                    'nvdcve-1.0-2009.json', 'nvdcve-1.0-2008.json', 
                    'nvdcve-1.0-2007.json', 'nvdcve-1.0-2006.json', 
                    'nvdcve-1.0-2005.json', 'nvdcve-1.0-2004.json', 
                    'nvdcve-1.0-2003.json', 'nvdcve-1.0-2002.json']

all_year_dict = {}
one_ngram_dict = {}
two_ngram_dict = {}
three_ngram_dict = {}
four_ngram_dict = {}
five_ngram_dict = {}
all_year_1gram_dict = {}
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
    one_ngram_dict = generate_ngram_dict_across_single_year(1)
    all_year_1gram_dict = merge_two_dicts(one_ngram_dict, all_year_1gram_dict)
    one_ngram_set = make_set_of_keys_given_dict(all_year_1gram_dict)
    for n in range(2, 6):
        if n == 2:
            two_ngram_dict = generate_ngram_dict_across_single_year(n)
            all_year_2gram_dict = merge_two_dicts(two_ngram_dict, all_year_2gram_dict)
            two_ngram_set = make_set_of_keys_given_dict(all_year_2gram_dict)
        elif n == 3:
            three_ngram_dict = generate_ngram_dict_across_single_year(n)
            all_year_3gram_dict = merge_two_dicts(three_ngram_dict, all_year_3gram_dict)
            three_ngram_set = make_set_of_keys_given_dict(all_year_3gram_dict)
        elif n == 4:
            four_ngram_dict = generate_ngram_dict_across_single_year(n)
            all_year_4gram_dict = merge_two_dicts(four_ngram_dict, all_year_4gram_dict)
            four_ngram_set = make_set_of_keys_given_dict(all_year_4gram_dict)
        elif n == 5:
            five_ngram_dict = generate_ngram_dict_across_single_year(n)
            all_year_5gram_dict = merge_two_dicts(five_ngram_dict, all_year_5gram_dict)
            five_ngram_set = make_set_of_keys_given_dict(all_year_5gram_dict)
    #Do the CPE now
    # for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
    #     print(cve_items_index)
    #     items = nvdcve_dict['CVE_Items'][cve_items_index]
    #     for node_index in range(len(items['configurations']['nodes'])):
    #         nodes = items['configurations']['nodes'][node_index]
    #         if 'children' in nodes:
    #             for children_index in range(len(nodes['children'])):
    #                 children = nodes['children'][children_index]
    #                 try:
    #                     for cpe_match_index in range(len(children['cpe_match'])):
    #                         cpe_matches = children['cpe_match'][cpe_match_index]
    #                         cpe_parsed_list = cpe_matches['cpe23Uri'].split(':')
    #                         add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
    #                 except:
    #                     #pdb.set_trace()
    #                     print('----------KeyError Occurred----------')
    #         else:
    #             try:
    #                 for cpe_match_index in range(len(nodes['cpe_match'])):
    #                     cpe_matches = nodes['cpe_match'][cpe_match_index]
    #                     cpe_parsed_list = cpe_matches['cpe23Uri'].split(':')
    #                     add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
    #             except:
    #                 #pdb.set_trace()
    #                 print('----------KeyError Occurred----------')
    #     cpe_product_name_set_keys = make_set_of_keys_given_dict(cpe_product_name)
    #     cpe_product_name_set_values = make_list_of_values_given_dict(cpe_product_name, cpe_product_name_set_keys)

#separate pns by spaces
# cpe_spaced_list = []
# for pns in cpe_product_name_set_keys:
#     cpe_spaced_list.append(pns.replace('_', ' '))
# cpe_set = set(cpe_spaced_list)
#print(cpe_set)


#separate maven names by spaces
for maven_names_idx in range(len(distinct_maven_names)):
    print('maven_idx:', maven_names_idx)
    temp_string = distinct_maven_names[maven_names_idx]
    temp_string = temp_string.replace('-', ' ')
    temp_string = temp_string.replace('_', ' ')
    distinct_maven_names[maven_names_idx] = temp_string
maven_set = set(distinct_maven_names)
#print(maven_set)

#This shows that there are no 2-word maven names.
mvn_1word = 0
mvn_2words = 0
for mvn_names in maven_set:
    if count_words(mvn_names) == 1:
        mvn_1word = mvn_1word + 1
    if count_words(mvn_names) == 2:
        mvn_2words = mvn_2words + 1
print('maven w/ 1 word:', mvn_1word)
print('maven w/ 2 words:', mvn_2words)
print('total # mvn:', len(maven_set))

#find intersection of CPE and Maven
# intersection_set = maven_set.intersection(cpe_set)
#print('intersection:', intersection_set)

#compare maven name and CPE description ngram set
maven_name_too_long_count = 0
one_intersect = {}
two_intersect = {}
three_intersect = {}
four_intersect = {}
five_intersect = {}
one_intersect = maven_set.intersection(one_ngram_set)
two_intersect = maven_set.intersection(two_ngram_set)
three_intersect = maven_set.intersection(three_ngram_set)
four_intersect = maven_set.intersection(four_ngram_set)
five_intersect = maven_set.intersection(five_ngram_set)
# for maven_names in distinct_maven_names:
#     temp_intersect = {}
#     word_count = count_words(maven_names)
#     if word_count == 1:
#         temp_intersect = maven_set.intersection(one_ngram_set)
#         one_intersect = one_intersect.update(temp_intersect)
#     elif word_count == 2:
#         temp_intersect = maven_set.intersection(two_ngram_set)
#         two_intersect = two_intersect.update(temp_intersect)
#     elif word_count == 3:
#         temp_intersect = maven_set.intersection(three_ngram_set)
#         three_intersect = three_intersect.update(temp_intersect)
#     elif word_count == 4:
#         temp_intersect = maven_set.intersection(four_ngram_set)
#         four_intersect = four_intersect.update(temp_intersect)
#     elif word_count == 5:
#         temp_intersect = maven_set.intersection(five_ngram_set)
#         five_intersect = five_intersect.update(temp_intersect)
#     else:
#         maven_name_too_long_count = maven_name_too_long_count + 1

new_one_dict = {}
new_two_dict = {}
new_three_dict = {}
new_four_dict = {}
new_five_dict = {}
for one_intersects in one_intersect:
    new_one_dict[one_intersects] = all_year_1gram_dict[one_intersects]
for two_intersects in two_intersect:
    new_two_dict[two_intersects] = all_year_2gram_dict[two_intersects]
for three_intersects in three_intersect:
    new_three_dict[three_intersects] = all_year_3gram_dict[three_intersects]
for four_intersects in four_intersect:
    new_four_dict[four_intersects] = all_year_4gram_dict[four_intersects]
for five_intersects in five_intersect:
    new_five_dict[five_intersects] = all_year_5gram_dict[five_intersects]

#merge the new dicts to all_year_dict with values being 'CVE-20XX-XXXX'
all_year_dict = merge_two_dicts(new_one_dict, new_two_dict)
all_year_dict = merge_two_dicts(all_year_dict, new_three_dict)
all_year_dict = merge_two_dicts(all_year_dict, new_four_dict)
all_year_dict = merge_two_dicts(all_year_dict, new_five_dict)

with open('pymongo-CVE_DESC_name_check.csv', mode='w') as csv_file:
    fieldnames = ['MCI_Name', 'CVEs', 'Number of CVEs']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    for key, value in all_year_dict.items():
        writer.writerow({'MCI_Name': key, 'CVEs': value, 'Number of CVEs': count_words(value)})

