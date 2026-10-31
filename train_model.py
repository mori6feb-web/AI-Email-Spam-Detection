import pickle
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# Example training data: 1 = spam, 0 = legitimate
emails = [
    "Congratulations you won a free prize click here",
    "Claim your cash reward now",
    "Urgent you have won a lottery",
    "Click this link to get free money",
    "Limited offer buy now",
    "You have been selected for a special gift",
    "Meeting is scheduled for tomorrow",
    "Please send me the class notes",
    "Are we still meeting for lunch today",
    "Your assignment deadline is Friday",
    "Thank you for your email",
    "Can we discuss the project after class",
]

labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]

model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("classifier", MultinomialNB()),
])

model.fit(emails, labels)

output_path = Path(__file__).with_name("spam_model.pkl")
with output_path.open("wb") as file:
    pickle.dump(model, file)

print("AI model trained successfully!")
print(f"Model saved to: {output_path}")

