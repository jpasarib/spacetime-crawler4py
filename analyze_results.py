import pickle
import re
from collections import Counter

try:
    with open("stopwords.txt", "r") as f:
        stopwords = set(word.strip().lower() for word in f.readlines())
except Exception as e:
    print(f"Stopword load failed: {e}")
    stopwords = set()

try:
    with open("word_counter.pkl", "rb") as f:
        word_counter = pickle.load(f)
except:
    word_counter = Counter()

filtered_words = Counter({word: count for word, count in word_counter.items() if word not in stopwords})
top_50 = filtered_words.most_common(50)

try:
    with open("longest_page.pkl", "rb") as f:
        longest_url, word_count = pickle.load(f)
except:
    longest_url, word_count = "", 0

with open("report_longest_page.txt", "w") as f:
    f.write(f"Longest page: {longest_url}\n")
    f.write(f"Word count: {word_count}\n")

with open("report_top_words.txt", "w") as f:
    f.write("Top 50 most common words (excluding stopwords):\n")
    for word, count in top_50:
        f.write(f"{word}: {count}\n")