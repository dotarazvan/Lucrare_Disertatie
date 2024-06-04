import sys
import numpy as np
import pandas as pd
import csv
import urllib.parse as parse
import pickle
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from numpy import *
from urllib.parse import unquote
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn import tree
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

# Install dependencies
# !{sys.executable} -m pip install -U numpy gensim python-Levenshtein nltk scikit-learn

# Download NLTK data
import nltk

nltk.download("punkt")

testXSS = []
testNORM = []
X_temp = []
X = []
y = []
xssnum = 0
notxssnum = 0

print("Gathering Data...")
# gather the XSS string and append the label of 1 to y array
with open("lib/testXSS.txt", "r") as f:
    testXSS = f.readlines()
print("*", sep=" ", end="", flush=True)
# parse out the query part of the URL
for line in testXSS:
    query = parse.urlsplit(line)[3]
    # try to remove open redirect vulns
    if "?http" in str(line):
        continue
    if "?url=http" in str(line):
        continue
    if "?fwd=http" in str(line):
        continue
    if "?path=http" in str(line):
        continue
    if "=http" in str(query):
        continue
    if "page=search" in str(query):
        continue
    if len(query) > 8:
        xssnum += 1
        # X_temp.append(query)
        X_temp.append(line)

# remove duplicates
dedup = list(dict.fromkeys(X_temp))
print("*", sep=" ", end="", flush=True)
# Add a feature to X and label to the y array
for line in dedup:
    # print("XSS => "+line)
    X.append(line)
    y.append(1)

X_temp = []
dedup = []
print("*", sep=" ", end="", flush=True)

# gather the list of normal string and append the label of 0 to y array
with open("lib/testNORM.txt", "r") as f:
    testNORM = f.readlines()

# parse out the query part of the URL
for line in testNORM:
    query = parse.urlsplit(line)[3]
    # if "http" in str(query):
    #     continue
    if len(query) > 3:
        notxssnum += 1
        X_temp.append(line)

# remove duplicates
dedup = list(dict.fromkeys(X_temp))
print("*", sep=" ", end="", flush=True)
# Add a feature to X and a label to the y array
for line in dedup:
    # print("NOT XSS => "+line)
    X.append(line)
    y.append(0)


def getVec(text):
    tagged_data = [
        TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)])
        for i, _d in enumerate(text)
    ]
    max_epochs = 25
    vec_size = 20
    alpha = 0.025

    model = Doc2Vec(
        vector_size=vec_size, alpha=alpha, min_alpha=0.00025, min_count=1, dm=1
    )
    model.build_vocab(tagged_data)
    print("Building the sample vector model...")
    features = []
    for epoch in range(max_epochs):
        print("*", sep=" ", end="", flush=True)
        model.random.seed(42)
        model.train(tagged_data, total_examples=model.corpus_count, epochs=model.epochs)
        # decrease the learning rate
        model.alpha -= 0.0002
        # fix the learning rate, no decay
        model.min_alpha = model.alpha
    model.save("lib/d2v.model")
    print()
    print("Model Saved")
    for i, line in enumerate(text):
        featureVec = [model.dv[i]]
        lineDecode = unquote(line)
        lineDecode = lineDecode.replace(" ", "")
        lowerStr = str(lineDecode).lower()
        feature1 = (
            int(lowerStr.count("<link"))
            + int(lowerStr.count("<object"))
            + int(lowerStr.count("<form"))
            + int(lowerStr.count("<embed"))
            + int(lowerStr.count("<ilayer"))
            + int(lowerStr.count("<layer"))
            + int(lowerStr.count("<style"))
            + int(lowerStr.count("<applet"))
            + int(lowerStr.count("<meta"))
            + int(lowerStr.count("<img"))
            + int(lowerStr.count("<iframe"))
            + int(lowerStr.count("<input"))
            + int(lowerStr.count("<body"))
            + int(lowerStr.count("<video"))
            + int(lowerStr.count("<button"))
            + int(lowerStr.count("<math"))
            + int(lowerStr.count("<picture"))
            + int(lowerStr.count("<map"))
            + int(lowerStr.count("<svg"))
            + int(lowerStr.count("<div"))
            + int(lowerStr.count("<a"))
            + int(lowerStr.count("<details"))
            + int(lowerStr.count("<frameset"))
            + int(lowerStr.count("<table"))
            + int(lowerStr.count("<comment"))
            + int(lowerStr.count("<base"))
            + int(lowerStr.count("<image"))
        )
        feature2 = (
            int(lowerStr.count("exec"))
            + int(lowerStr.count("fromcharcode"))
            + int(lowerStr.count("eval"))
            + int(lowerStr.count("alert"))
            + int(lowerStr.count("getelementsbytagname"))
            + int(lowerStr.count("write"))
            + int(lowerStr.count("unescape"))
            + int(lowerStr.count("escape"))
            + int(lowerStr.count("prompt"))
            + int(lowerStr.count("onload"))
            + int(lowerStr.count("onclick"))
            + int(lowerStr.count("onerror"))
            + int(lowerStr.count("onpage"))
            + int(lowerStr.count("confirm"))
            + int(lowerStr.count("marquee"))
        )
        feature3 = int(lowerStr.count(".js"))
        feature4 = int(lowerStr.count("javascript"))
        feature5 = int(len(lowerStr))
        feature6 = (
            int(lowerStr.count("<script"))
            + int(lowerStr.count("&lt;script"))
            + int(lowerStr.count("%3cscript"))
            + int(lowerStr.count("%3c%73%63%72%69%70%74"))
        )
        feature7 = (
            int(lowerStr.count("&"))
            + int(lowerStr.count("<"))
            + int(lowerStr.count(">"))
            + int(lowerStr.count('"'))
            + int(lowerStr.count("'"))
            + int(lowerStr.count("/"))
            + int(lowerStr.count("%"))
            + int(lowerStr.count("*"))
            + int(lowerStr.count(";"))
            + int(lowerStr.count("+"))
            + int(lowerStr.count("="))
            + int(lowerStr.count("%3C"))
        )
        feature8 = int(lowerStr.count("http"))

        featureVec = np.append(featureVec, feature1)
        featureVec = np.append(featureVec, feature2)
        featureVec = np.append(featureVec, feature3)
        featureVec = np.append(featureVec, feature4)
        featureVec = np.append(featureVec, feature5)
        featureVec = np.append(featureVec, feature6)
        featureVec = np.append(featureVec, feature7)
        featureVec = np.append(featureVec, feature8)
        features.append(featureVec)
    return features


features = getVec(X)
features_dict = {"data": X, "features": features, "label": y}

print("Test Sample: " + X[0])
print("Features: " + str(features[0]))
print("\nLabel:\033[1;31;1m XSS(1)/\033[1;32;1m NOT XSS(0)\033[0;0m: " + str(y[0]))

np.random.seed(42)

X_train, X_test, y_train, y_test = train_test_split(
    features, y, test_size=0.3, random_state=42
)

my_classifier1 = tree.DecisionTreeClassifier(random_state=42)
print(my_classifier1)
print()

my_classifier2 = SVC(kernel="linear", random_state=42)
print(my_classifier2)
print()

my_classifier3 = GaussianNB()
print(my_classifier3)
print()

my_classifier4 = KNeighborsClassifier(n_neighbors=25, weights="uniform")
print(my_classifier4)
print()

my_classifier5 = RandomForestClassifier(random_state=42)
print(my_classifier5)
print()

my_classifier6 = MLPClassifier(max_iter=2000, random_state=42)
print(my_classifier6)
print()

print("Training Classifier #1 DecisionTreeClassifier")
my_classifier1.fit(X_train, y_train)
print("Training Classifier #2 SVC")
my_classifier2.fit(X_train, y_train)
print("Training Classifier #3 GaussianNB")
my_classifier3.fit(X_train, y_train)
print("Training Classifier #4 KNeighborsClassifier")
my_classifier4.fit(X_train, y_train)
print("Training Classifier #5 RandomForestClassifier")
my_classifier5.fit(X_train, y_train)
print("Training Classifier #6 MLPClassifier")
my_classifier6.fit(X_train, y_train)

predictions1 = my_classifier1.predict(X_test)
predictions2 = my_classifier2.predict(X_test)
predictions3 = my_classifier3.predict(X_test)
predictions4 = my_classifier4.predict(X_test)
predictions5 = my_classifier5.predict(X_test)
predictions6 = my_classifier6.predict(X_test)

print("Accuracy Score #1: {:.1%}".format(accuracy_score(y_test, predictions1)))
print("Accuracy Score #2: {:.1%}".format(accuracy_score(y_test, predictions2)))
print("Accuracy Score #3: {:.1%}".format(accuracy_score(y_test, predictions3)))
print("Accuracy Score #4: {:.1%}".format(accuracy_score(y_test, predictions4)))
print("Accuracy Score #5: {:.1%}".format(accuracy_score(y_test, predictions5)))
print("Accuracy Score #6: {:.1%}".format(accuracy_score(y_test, predictions6)))

print("Classification Report #1 DecisionTreeClassifier")
print(classification_report(y_test, predictions1))
print("Classification Report #2 SVC")
print(classification_report(y_test, predictions2))
print("Classification Report #3 GaussianNB")
print(classification_report(y_test, predictions3))
print("Classification Report #4 KNeighborsClassifier")
print(classification_report(y_test, predictions4))
print("Classification Report #5 RandomForestClassifier")
print(classification_report(y_test, predictions5))
print("Classification Report #6 MLPClassifier")
print(classification_report(y_test, predictions6))

print("\nConfusion Matrix #1 DecisionTreeClassifier")
print(confusion_matrix(y_test, predictions1))
print("\nConfusion Matrix #2 SVC")
print(confusion_matrix(y_test, predictions2))
print("\nConfusion Matrix #3 GaussianNB")
print(confusion_matrix(y_test, predictions3))
print("\nConfusion Matrix #4 KNeighborsClassifier")
print(confusion_matrix(y_test, predictions4))
print("\nConfusion Matrix #5 RandomForestClassifier")
print(confusion_matrix(y_test, predictions5))
print("\nConfusion Matrix #6 MLPClassifier")
print(confusion_matrix(y_test, predictions6))

print("Training Classifier #1 DecisionTreeClassifier")
my_classifier1.fit(features, y)
print("Training Classifier #2 SVC")
my_classifier2.fit(features, y)
print("Training Classifier #3 GaussianNB")
my_classifier3.fit(features, y)
print("Training Classifier #4 KNeighborsClassifier")
my_classifier4.fit(features, y)
print("Training Classifier #5 RandomForestClassifier")
my_classifier5.fit(features, y)
print("Training Classifier #6 MLPClassifier")
my_classifier6.fit(features, y)

filename1 = "lib/DecisionTreeClassifier.sav"
pickle.dump(my_classifier1, open(filename1, "wb"))

filename2 = "lib/SVC.sav"
pickle.dump(my_classifier2, open(filename2, "wb"))

filename3 = "lib/GaussianNB.sav"
pickle.dump(my_classifier3, open(filename3, "wb"))

filename4 = "lib/KNeighborsClassifier.sav"
pickle.dump(my_classifier4, open(filename4, "wb"))

filename5 = "lib/RandomForestClassifier.sav"
pickle.dump(my_classifier5, open(filename5, "wb"))

filename6 = "lib/MLPClassifier.sav"
pickle.dump(my_classifier6, open(filename6, "wb"))

loaded_model1 = pickle.load(open(filename1, "rb"))
loaded_model2 = pickle.load(open(filename2, "rb"))
loaded_model3 = pickle.load(open(filename3, "rb"))
loaded_model4 = pickle.load(open(filename4, "rb"))
loaded_model5 = pickle.load(open(filename5, "rb"))
loaded_model6 = pickle.load(open(filename6, "rb"))

testXSS = [
    "<script>alert('xss')</script><script><script>",
    "hellomo",
    "https://store.bentley.com/en/shop/search?term=%22%3E%3Cdetails%20open%20ontoggle=prompt(1337)%3ExxLouisLouisLouis",
    "ghfdhgdhjgd",
    "uid%3D19%26list_page%3D%22%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C/script%3E",
    "&template=en_search_error&postalCode=\\';alert(0)//",
    "&where=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E&",
    "&where=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E&loctypes=1003%2C1001%2C1000%2C1%2C9%2C5%2C11%2C13%2C19%2C20&from=hdr_localsearch",
    "http://mydata.com/sad/sd/qwd/qwde/qwe/?sessionid=12",
    "http://mydata.com?id=script",
    "&';}},{scope:'email,user_about_me,user_hometown,user_interests,user_likes,user_status,user_website,user_birthday,p",
    "http://myurl.com?<script",
    "http://mydata.com?script=script",
    'composite_search=1&keyword="/><script>alert("Xss:Vijayendra")</script>',
    "http://mysite.com?srtalert",
    "script",
    "alert",
    "Search=%22%3E'%3E%3CSCRIPT%20SRC=http://br.zone-h.org/testes/xss.js%3E%3C/SCRIPT%3E?",
    "id=15%3Cscript%3Ealert%28document.cookie%29%3C/script%3E",
    'composite_search=1&keyword="/><script>alert("Xss:Vijayendra")</script>',
    "id=123&href=abdc<a<script>alert(1)",
    "<<<<<<>>>>></>,><><>",
    "alert()alert()",
    "alertalert",
    "?url=http://localhost:8888/notebooks/Documents/MachineLearning/Practical%20Machine%20Learning",
    "<script<script",
    "<scriptalert",
    "httphttphttp",
    "https://disqus.com/?ref_noscript",
    "I am a string",
    '<img src="javascript:alert(1)/>"',
    "HelloWorld!",
    "http://mysite.com?<script>",
    "<input type=\"text\" value=`` <div/onmouseover='alert(471)'>X</div>",
    '<img \x47src=x onerror="javascript:alert(324)">',
    '<a href="\xE2\x80\x87javascript:javascript:alert(183)" id="fuzzelement1">test</a>',
    "<body onscroll=javascript:alert(288)><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><br><br><br><br><br><br>...<br><br><br><br><input autofocus>",
    '<meta charset="mac-farsi">¼script¾javascript:alert(379)¼/script¾',
    '<HTML xmlns:xss><?import namespace=(493)s" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID=(494)s"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(420)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>',
]

Xnew = getVec(testXSS)

ynew1 = loaded_model1.predict(Xnew)
ynew2 = loaded_model2.predict(Xnew)
ynew3 = loaded_model3.predict(Xnew)
ynew4 = loaded_model4.predict(Xnew)
ynew5 = loaded_model5.predict(Xnew)
ynew6 = loaded_model6.predict(Xnew)

xssCount = 0
notXssCount = 0
for i in range(len(Xnew)):
    score = (
        (0.175 * ynew1[i])
        + (0.15 * ynew2[i])
        + (0.05 * ynew3[i])
        + (0.075 * ynew4[i])
        + (0.25 * ynew5[i])
        + (0.3 * ynew6[i])
    )
    if score >= 0.5:
        print("\033[1;31;1mXSS\033[0;0m => " + testXSS[i])
        xssCount += 1
    else:
        print("\033[1;32;1mNOT XSS\033[0;0m => " + testXSS[i])
        notXssCount += 1

print()
print("*------------- RESULTS -------------*")
print("\033[1;31;1mXSS\033[0;0m => " + str(xssCount))
print("\033[1;32;1mNOT XSS\033[0;0m => " + str(notXssCount))
