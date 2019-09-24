import pandas as pd
import nltk
from nltk import word_tokenize, sent_tokenize
import re
from nltk.corpus import stopwords
from nltk.util import ngrams
from collections import Counter
from collections import OrderedDict   
from itertools import chain
import itertools
import math

df0 = pd.read_pickle('/home/jae/git/celadon/maven/outputs/parsed_mvn_cent_idx_06032019.pickle')   
df1 = pd.read_pickle('/home/jae/share/cveid_description_cpes.pickle') 

def get_uniq_set_gr_art(df0):
    set_gr_art = []
    for i in df0.keys():
            try:
                df0[i]['group_u']
                set_gr_art.append([df0[i]['group_u'].lower(), df0[i]['artifact_u'].lower()])
            except:
                pass

    uniq_set_gr_art = list(set(map(tuple, set_gr_art)))
    return uniq_set_gr_art
                                  
def parse_name(name, special_char):
    num_char = sum([x in name for x in special_char])
    if num_char !=0:
        char_index = [special_char.index(x) for x in special_char if x in name]
        if len(char_index) > 1:
            name = name.split(special_char[char_index[0]])
            for i in char_index[1:]:
                name = [x.split(special_char[i]) for x in name] 
                name = sum(name,[])
            while '' in name:
                name.remove('')
        if len(char_index) == 1:
            name = name.split(special_char[char_index[0]])
            while '' in name:
                name.remove('')
    if type(name) == str:
        name = [name]
    return name

def remove_string_special_characters(s):
    stripped = re.sub('[^\w\s]', '', s)
    stripped = re.sub('_', '', stripped)
    stripped = re.sub('\s+', ' ', stripped)
    stripped = stripped.strip()

    return stripped

def get_doc(sents):
    doc_info = []
    i = 0
    for sent in sents:
        i += 1
        count = count_words(sent)
        temp = {'sent_id' :i, 'sent_length':count}
        doc_info.append(temp)
    return doc_info

def count_words(sent):
    count = 0
    words = word_tokenize(sent)
    for word in words:
        count += 1
    return count

        
def create_freq_dict_words(ga_name):
    words = list(itertools.chain(*ga_name))
    freq_dict = {}
    for word in words:
        word = word.lower()
        if word in freq_dict:
            freq_dict[word] +=1
        else:
            freq_dict[word] = 1
    return freq_dict

def create_freq_dict_sents(sents):
    i = 0
    freqDict_list = []
    for sent in sents:
        i += 1
        freq_dict = {}
        words = word_tokenize(sent)
        for word in words:
            word = word.lower()
            if word in freq_dict:
                freq_dict[word] += 1
            else:
                freq_dict[word] = 1
            temp = {'sent_id' : i, 'freq_dict': freq_dict}
        freqDict_list.append(temp)
    return freqDict_list

def computeIDF_sent(sent_info, freqDict_list, all_freq_dict):
    IDF_scores = []
    counter = 0
    for dict in freqDict_list:
        counter += 1
        for k in dict['freq_dict'].keys():
            #count = sum([k in tempDict['freq_dict'] for tempDict in freqDict_list])
            temp = {'sent_id' : counter, 'IDF_score' : math.log(118880/all_freq_dict[k]), 'key' :k}
            IDF_scores.append(temp)

    return IDF_scores
    
def computeIDF_words(ga_name, freq_dict):
    IDF_scores = []
    counter = 0
    total_word_count = sum(freq_dict.values())
    for ga in ga_name:
        counter += 1
        for ga_str  in ga:
            count = freq_dict[ga_str]
            temp = {'ga_id' : counter, 'IDF_score' : math.log(total_word_count/count), 'key' :ga_str}
            IDF_scores.append(temp)

    return IDF_scores

uniq_set_gr_art = get_uniq_set_gr_art(df0)
ga_name = []
for s in uniq_set_gr_art:
    ga_name.append(list((parse_name(s[0],'.') + parse_name(s[1],['_','-']))))

freq_dict = create_freq_dict_words(ga_name) 
IDF_scores_ga = computeIDF_words(ga_name, freq_dict) 

str_cve_dict = {}
all_freq_dict = {}
for cve in df1.keys():
    sents = df1[cve]['description']
    text_sents = sent_tokenize(sents)
    text_sents_clean = [remove_string_special_characters(s) for s in text_sents]
    for sent in text_sents_clean:
        words = word_tokenize(sent)
        for word in words:
            word = word.lower()
            if word in str_cve_dict:
                str_cve_dict[word] = list(set(str_cve_dict[word] + [cve]))
                all_freq_dict[word] = len(str_cve_dict[word])
            else:
                str_cve_dict[word] = [cve]
                all_freq_dict[word] = 1


    
cve = 'CVE-2013-7397'
sents = df1[cve]['description']
text_sents = sent_tokenize(sents)
text_sents_clean = [remove_string_special_characters(s) for s in text_sents]
sent_info = get_doc(text_sents_clean)
freqDict_list = create_freq_dict_sents(text_sents_clean)
IDF_scores_sents = computeIDF_sent(sent_info, freqDict_list, all_freq_dict)
IDF_scores_cves = [{'cve_id':cve, **item} for item in IDF_scores_sents]
IDF_scores_sents


ind = ga_name.index(['org', 'asynchttpclient', 'async', 'http', 'client'])
IDF_multi = {}
for dict in IDF_scores_ga:
    if dict['ga_id'] == ind+1:
        for x in IDF_scores_sents:
                if dict['key'] == x['key']:
                    IDF_multi[x['key']] = dict['IDF_score'] * x['IDF_score']
            
