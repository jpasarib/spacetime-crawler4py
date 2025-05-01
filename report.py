import pickle
import os
from collections import Counter

def load_pickle(file, default):
    return pickle.load(open(file, "rb")) if os.path.exists(file) else default

def load_stopwords():
    if os.path.exists("stopwords.txt"):
        with open("stopwords.txt", "r") as f:
            return set(word.strip().lower() for word in f.readlines())
    return set()

def generate_report():
    unique_urls = load_pickle("unique_urls.pkl", set())
    subdomain_counts = load_pickle("subdomain_counts.pkl", {})
    longest_page_info = load_pickle("longest_page_info.pkl", ("", 0))
    word_counter = load_pickle("word_counter.pkl", Counter())
    stopwords = load_stopwords()

    filtered_words = Counter({word: count for word, count in word_counter.items() if word not in stopwords})
    top_50_words = filtered_words.most_common(50)

    with open("report.txt", "w") as f:
        f.write("====== CRAWLER REPORT ======\n\n")

        f.write(f"Total unique pages found: {len(unique_urls)}\n\n")

        f.write("Longest page by word count:\n")
        f.write(f"URL: {longest_page_info[0]}\n")
        f.write(f"Word Count: {longest_page_info[1]}\n\n")

        f.write("Subdomain counts (sorted):\n")
        for subdomain, count in sorted(subdomain_counts.items()):
            f.write(f"{subdomain}, {count}\n")
        f.write("\n")

        f.write("Top 50 most common words (excluding stopwords):\n")
        for word, freq in top_50_words:
            f.write(f"{word}: {freq}\n")

    print("Report generated as report.txt")

if __name__ == "__main__":
    generate_report()