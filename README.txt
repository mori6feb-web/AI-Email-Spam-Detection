AI-BASED EMAIL SPAM DETECTION USING MACHINE LEARNING
====================================================

IMPORTANT: This emergency-compatible version avoids pandas, NumPy, and scikit-learn,
because Windows Application Control blocked a compiled library on the original setup.
The classifier is a small Multinomial Naive Bayes implementation using Python's
standard library only.

HOW TO RUN
----------
1. Extract this ZIP into a folder.
2. Open that folder in VS Code.
3. Open Terminal > New Terminal.
4. Run: python app.py
5. Open this address in your browser: http://127.0.0.1:8000
6. Paste a message and click "Detect Spam".

No pip install is needed. Python 3.10+ is recommended.

FILES
-----
app.py             Web interface and Naive Bayes classifier
spam_dataset.csv   Labeled sample training data
requirements.txt   No third-party dependencies
README.txt         This guide

PROJECT OVERVIEW
----------------
Title: AI-Based Email Spam Detection Using Machine Learning
Algorithm: Multinomial Naive Bayes
Text processing: lowercase tokenization and word frequency counts
Output: Spam/Ham prediction and estimated spam probability

NOTE
----
The included dataset is small for demonstration. For a formal evaluation, use a
larger approved public dataset and report test-set metrics. A message classifier
can make mistakes and should not be used as the sole basis for security decisions.
