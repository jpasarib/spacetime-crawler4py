import pickle

with open("visited_urls.pkl", "rb") as f:
    visited = pickle.load(f)

print(f"Total visited URLs: {len(visited)}")