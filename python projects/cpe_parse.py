import json
import csv
import re

def count_words(how_many_words_in_this_string):
    """Counts words in the given string"""
    if isinstance(how_many_words_in_this_string, str):
        lengthList = how_many_words_in_this_string.split()
        return len(lengthList)
    else:
        raise ValueError("Input must be a String")

def count_occurrences_in_list_of_strings(word_to_count, description_string_list):
    """Counts the number of occurrences of a word in a given string"""
    num_occurrences = description_string_list.count(word_to_count)
    return num_occurrences

def count_occurrences_in_string(word_to_count, long_string):
    """Counts the number of occurences of a word in a long string."""
    #but counts occurrences within strings as well
    count = long_string.count(word_to_count)
    return count

def get_unique_words(string_list):
    """Returns the nubmer of unique words given a list of strings."""
    uniqueWords = []
    for i in string_list:
        if not i in uniqueWords:
            uniqueWords.append(i)
    return uniqueWords

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
        
def add_single_year_dict_to_corpus_dict(all_year_dict, single_year_dict, filename):
    """Adds the single year dict into the structure for the corpus dict."""
    all_year_dict[filename] = single_year_dict

def add_all_values_for_specific_key(current_word, all_year_dict):
    """Adds all of the values of a key given the corpus dict."""
    occurrences = 0
    list_of_years = list(all_year_dict.keys())
    for years in list_of_years:
        if current_word in all_year_dict[years]:
            occurrences = occurrences + all_year_dict[years][current_word]
    return occurrences
        
def get_specific_version_count(all_year_dict, files, cve_items_index, versions):
    """Gets the count of versions from the dictionary of versions."""
    if versions in all_year_dict[files][cve_items_index]:
        version_count = all_year_dict[files][cve_items_index][versions]
    else:
        version_count = 0
    return version_count

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

cve_json_filenames=['nvdcve-1.0-2019.json', 'nvdcve-1.0-2018.json', 
                    'nvdcve-1.0-2017.json', 'nvdcve-1.0-2016.json', 
                    'nvdcve-1.0-2015.json', 'nvdcve-1.0-2014.json', 
                    'nvdcve-1.0-2013.json', 'nvdcve-1.0-2012.json', 
                    'nvdcve-1.0-2011.json', 'nvdcve-1.0-2010.json', 
                    'nvdcve-1.0-2009.json', 'nvdcve-1.0-2008.json', 
                    'nvdcve-1.0-2007.json', 'nvdcve-1.0-2006.json', 
                    'nvdcve-1.0-2005.json', 'nvdcve-1.0-2004.json', 
                    'nvdcve-1.0-2003.json', 'nvdcve-1.0-2002.json']

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

#print(all_year_dict)

with open('cpe_parse3.csv', mode='w') as csv_file:
        fieldnames = ['ID', 'Has_Description', 'Description', 'Description_WC',
                      'Vendor_Name', 'Vendor_Count', 'Product_Name', 
                      'Product_Count', 'Version_Value', 'Version_Count', 
                      'CPE_System_Type', 'CPE_System_Type_Count',
                      'CPE_Vendor_Name', 'CPE_Vendor_Name_Count', 
                      'CPE_Product_Name', 'CPE_Product_Name_Desc_Count',
                      'CPE_Product_Name_Desc_Count_Sum', 
                      'CPE_Product_Name_Spaced_List', 
                      'CPE_Product_Name_Partial_Match_Count', 
                      'CPE_Product_Name_Ngram_Count', 
                      'CPE_Product_Name_Ngram_Count_Sum', 
                      'CPE_Product_Name_Count', 'CPE_Product_Name_Count_Sum',
                      'CPE_Product_Name_Categories_Count', 
                      'CPE_Versions', 'CPE_Versions_Count', 'CPE_Update',
                      'CPE_Update_Count']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for files in cve_json_filenames:
            with open(files, 'r', encoding="utf8") as f:
                nvdcve_dict = json.load(f)
            for cve_items_index in range(len(nvdcve_dict['CVE_Items'])):
                cpe_system_type = {}
                cpe_vendor_name = {}
                cpe_product_name = {}
                cpe_versions = {}
                cpe_update = {}
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
                                    add_1_to_dict_if_exist(cpe_system_type, cpe_parsed_list[2])
                                    add_1_to_dict_if_exist(cpe_vendor_name, cpe_parsed_list[3])
                                    add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
                                    add_1_to_dict_if_exist(cpe_versions, cpe_parsed_list[5])
                                    add_1_to_dict_if_exist(cpe_update, cpe_parsed_list[6])
                            except:
                                #pdb.set_trace()
                                print('----------KeyError Occurred----------')
                    else:
                        try:
                            for cpe_match_index in range(len(nodes['cpe_match'])):
                                cpe_matches = nodes['cpe_match'][cpe_match_index]
                                cpe_parsed_list = cpe_matches['cpe23Uri'].split(':')
                                add_1_to_dict_if_exist(cpe_system_type, cpe_parsed_list[2])
                                add_1_to_dict_if_exist(cpe_vendor_name, cpe_parsed_list[3])
                                add_1_to_dict_if_exist(cpe_product_name, cpe_parsed_list[4])
                                add_1_to_dict_if_exist(cpe_versions, cpe_parsed_list[5])
                                add_1_to_dict_if_exist(cpe_update, cpe_parsed_list[6])
                        except:
                            #pdb.set_trace()
                            print('----------KeyError Occurred----------')
                cpe_system_type_set_keys = make_set_of_keys_given_dict(cpe_system_type)
                cpe_vendor_name_set_keys = make_set_of_keys_given_dict(cpe_vendor_name)
                cpe_product_name_set_keys = make_set_of_keys_given_dict(cpe_product_name)
                cpe_versions_set_keys = make_set_of_keys_given_dict(cpe_versions)
                cpe_update_set_keys = make_set_of_keys_given_dict(cpe_update)
                cpe_system_type_set_values = make_list_of_values_given_dict(cpe_system_type, cpe_system_type_set_keys)
                cpe_vendor_name_set_values = make_list_of_values_given_dict(cpe_vendor_name, cpe_vendor_name_set_keys)
                cpe_product_name_set_values = make_list_of_values_given_dict(cpe_product_name, cpe_product_name_set_keys)
                cpe_versions_set_values = make_list_of_values_given_dict(cpe_versions, cpe_versions_set_keys)
                cpe_update_set_values = make_list_of_values_given_dict(cpe_update, cpe_update_set_keys)
                #separate pns by spaces
                cpe_spaced_list = []
                for pns in cpe_product_name_set_keys:
                    cpe_spaced_list.append(pns.replace('_', ' '))
                if 'a' in cpe_system_type.keys():
                    cve_items = nvdcve_dict['CVE_Items'][cve_items_index]
                    cve_cve_category = cve_items['cve']
                    cve_description = cve_cve_category['description']
                    description_string = cve_description['description_data'][0]['value']
                    has_description = 'True'
                    if description_string is None:
                        has_description = 'False'
                    cve_item_description_words_list = re.sub("[^\w]", " ", description_string).split()
                    cve_item_ID = cve_items['cve']['CVE_data_meta']['ID']
                    #ONLY sets vendor details if they exist. Otherwise, they DNE.
                    all_year_dict_curr_idx = all_year_dict[files][cve_items_index]
                    all_year_2gram_curr_idx = all_year_2gram_dict[files][cve_items_index]
                    all_year_3gram_curr_idx = all_year_3gram_dict[files][cve_items_index]
                    all_year_4gram_curr_idx = all_year_4gram_dict[files][cve_items_index]
                    all_year_5gram_curr_idx = all_year_5gram_dict[files][cve_items_index]
                    list_of_pns_in_desc = []
                    cpe_pn_count = 0
                    cpe_pn_sum = 0
                    for cpe_pns in cpe_product_name_set_keys:
                        if cpe_pns in all_year_dict_curr_idx:
                            cpe_pn_count = all_year_dict_curr_idx[cpe_pns]
                        else:
                            cpe_pn_count = 0
                        list_of_pns_in_desc.append(cpe_pn_count)
                        cpe_pn_sum += cpe_pn_count
                    cpe_category_count = 0
                    cpe_product_name_count_sum = 0
                    for cpe_categories_count in cpe_product_name_set_values:
                        cpe_category_count += 1
                        cpe_product_name_count_sum += cpe_categories_count
                    ngram_frequency_list = []
                    ngram_frequency_sum = 0
                    cpe_ngram_count = 0
                    #n-grams count for the spaced list
                    for cpe_pns in cpe_spaced_list:
                        n = count_words(cpe_pns)
                        if n == 1:
                            if cpe_pns in all_year_dict_curr_idx:
                                cpe_ngram_count = all_year_dict_curr_idx[cpe_pns]
                            else:
                                cpe_ngram_count = 0
                            ngram_frequency_list.append(cpe_ngram_count)
                            ngram_frequency_sum += cpe_ngram_count
                        elif n == 2: 
                            if cpe_pns in all_year_2gram_curr_idx:
                                cpe_ngram_count = all_year_2gram_curr_idx[cpe_pns]
                            else:
                                cpe_ngram_count = 0
                            ngram_frequency_list.append(cpe_ngram_count)
                            ngram_frequency_sum += cpe_ngram_count
                        elif n == 3:
                            if cpe_pns in all_year_3gram_curr_idx:
                                cpe_ngram_count = all_year_3gram_curr_idx[cpe_pns]
                            else:
                                cpe_ngram_count = 0
                            ngram_frequency_list.append(cpe_ngram_count)
                            ngram_frequency_sum += cpe_ngram_count
                        elif n == 4:
                            if cpe_pns in all_year_4gram_curr_idx:
                                cpe_ngram_count = all_year_4gram_curr_idx[cpe_pns]
                            else:
                                cpe_ngram_count = 0
                            ngram_frequency_list.append(cpe_ngram_count)
                            ngram_frequency_sum += cpe_ngram_count
                        elif n == 5:
                            if cpe_pns in all_year_5gram_curr_idx:
                                cpe_ngram_count = all_year_5gram_curr_idx[cpe_pns]
                            else:
                                cpe_ngram_count = 0
                            ngram_frequency_list.append(cpe_ngram_count)
                            ngram_frequency_sum += cpe_ngram_count
                    cpe_partial_match = 0
                    for ngrams in cpe_spaced_list:
                        for partial in ngrams.split():
                            if partial in all_year_dict_curr_idx:
                                cpe_partial_match += all_year_dict_curr_idx[partial]
                    #cpe_partial_match = cpe_partial_match - ngram_frequency_sum
                    if cve_cve_category['affects']['vendor']['vendor_data']:
                        vendor_data = cve_cve_category['affects']['vendor']['vendor_data']
                        vendor_name = vendor_data[0]['vendor_name']
                        if vendor_name in all_year_dict[files][cve_items_index].keys():
                            vendor_count = all_year_dict_curr_idx[vendor_name]
                        product_data_0 = vendor_data[0]['product']['product_data'][0]
                        product_name =  product_data_0['product_name']
                        if product_name in all_year_dict_curr_idx.keys():
                            product_count = all_year_dict_curr_idx[product_name]
                        version_data = product_data_0['version']['version_data']
                        version_value = version_data[0]['version_value']
                        version_count = get_specific_version_count(all_year_dict, files, cve_items_index, version_value)
                        for versions in range(1, len(version_data)):
                            version_value = version_value + ',' + version_data[versions]['version_value']
                            if versions in all_year_dict_curr_idx.keys():
                                version_count = version_count + ',' + get_specific_version_count(all_year_dict, files, cve_items_index, versions)
                    else:
                        vendor_name = 'DNE'
                        vendor_count = 'n/a'
                        product_name = 'DNE'
                        product_count = 'n/a'
                        version_value = 'DNE'
                        version_count = 'n/a'
                    print(cve_item_ID)
                    writer.writerow({'ID': cve_item_ID, 
                                     'Has_Description': has_description,
                                     'Description': description_string, 
                                     'Description_WC': count_words(description_string), 
                                     'Vendor_Name': vendor_name,
                                     'Vendor_Count': vendor_count,
                                     'Product_Name': product_name, 
                                     'Product_Count': product_count,
                                     'Version_Value': version_value,
                                     'Version_Count': version_count, 
                                     'CPE_System_Type': cpe_system_type_set_keys,
                                     'CPE_System_Type_Count': cpe_system_type_set_values,
                                     'CPE_Vendor_Name': cpe_vendor_name_set_keys,
                                     'CPE_Vendor_Name_Count': cpe_vendor_name_set_values,
                                     'CPE_Product_Name': cpe_product_name_set_keys,
                                     'CPE_Product_Name_Desc_Count': list_of_pns_in_desc, 
                                     'CPE_Product_Name_Desc_Count_Sum': cpe_pn_sum, 
                                     'CPE_Product_Name_Spaced_List': cpe_spaced_list,
                                     'CPE_Product_Name_Partial_Match_Count': cpe_partial_match, 
                                     'CPE_Product_Name_Ngram_Count': ngram_frequency_list,
                                     'CPE_Product_Name_Ngram_Count_Sum': ngram_frequency_sum, 
                                     'CPE_Product_Name_Count': cpe_product_name_set_values,
                                     'CPE_Product_Name_Count_Sum': cpe_product_name_count_sum,
                                     'CPE_Product_Name_Categories_Count': cpe_category_count,
                                     'CPE_Versions': cpe_versions_set_keys, 
                                     'CPE_Versions_Count': cpe_versions_set_values,
                                     'CPE_Update': cpe_update_set_keys,
                                     'CPE_Update_Count': cpe_update_set_values})