# %% [markdown]
# # CSCI 4178, Lecture 14. Comparing detectors on a time-ordered split
#
# **Dalhousie University, Faculty of Computer Science. Fall 2026.**
#
# This notebook is the in-class activity. It trains seven classifiers on fourteen days of
# connection records and compares them the way a security team would: by a ranking metric, by
# the share of attacks caught inside an alert budget, and by attack family.
#
# **You write no Python.** Run the cells in order and read the output. One cell in stage 5
# asks you to change a single number.
#
# **Run one stage at a time.** Do not use *Runtime, Run all*: two cells are answers that are
# meant to be read after you have written yours down.
#
# | Stage | Cells | Minutes | What you do |
# | --- | --- | --- | --- |
# | 0 | setup | 1 | Load the data. |
# | 1 | predict | 4 | Rank four models before anything is trained. |
# | 2 | rank | 9 | Train seven models, read the ranking and its uncertainty. |
# | 3 | budget | 9 | Move from a ranking metric to an operating point. |
# | 4 | family | 8 | Find the family nobody detects, and determine why. |
# | 5 | extras | spare | Importance measures, overfitting, decision boundaries. |
#
# The dataset is synthetic. It was built for the course referenced below and has a realistic
# intrusion-detection feature schema, fourteen days of time structure, two sites with different
# base rates, five attack families, a 2.8 per cent attack rate and duplicated records.
#
# ---
#
# Derived from **Lab 3a, *Comparing classifiers on a time-ordered split***, in
# *Machine Learning for Cybersecurity* by Ali Al Bataineh,
# <https://aalbata.github.io/machine-learning-for-cybersecurity/>.
# Course text CC BY 4.0, code MIT. The dataset `flows.csv` is fetched from that repository.
# Restructured into stages for CSCI 4178; the analysis in stages 3 and 4 is new.

# %% [markdown]
# ## Stage 0. Setup
#
# Imports, then the data. Training uses days 0 to 9 and testing days 10 to 13. Duplicated
# records are removed before the split, so that no record appears in both parts.

# %%
import os
import time
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")

URL = "https://raw.githubusercontent.com/aalbata/machine-learning-for-cybersecurity/main/data/flows.csv"
flows = pd.read_csv(URL).drop_duplicates().reset_index(drop=True)

train = flows[flows["day"] <= 9]
test = flows[flows["day"] >= 10]
ytr = train["label"].to_numpy()
yte = test["label"].to_numpy()
family = test["attack_type"].to_numpy()
n_days = test["day"].nunique()
SEEDS = [0, 1, 2, 3, 4]

print(f"training  days 0-9    {len(train):>7,} records   {ytr.sum():>4} attacks")
print(f"test      days 10-13  {len(test):>7,} records   {yte.sum():>4} attacks   over {n_days} days")
print(f"attack rate: training {ytr.mean():.3%}, test {yte.mean():.3%}")
print(f"\ncolumns: {', '.join(flows.columns)}")

# %% [markdown]
# ## Stage 1. Predict
#
# Nothing has been trained yet. Four of the seven models are listed below, one from each family
# on the reference slide:
#
# | Model | What is fitted |
# | --- | --- |
# | `logistic regression` | One weight per feature, summed and passed through the logistic function. |
# | `Gaussian naive Bayes` | One normal distribution per feature per class; features assumed independent. |
# | `decision tree` | Nested threshold tests, one feature at a time. Depth limited to 8. |
# | `random forest` | Average of 300 trees, each on a bootstrap sample and a feature subset. |
#
# Rank them by the average precision you expect each to reach on the test days, best first.
# Write the four names into the list below, exactly as spelled above, and run the cell. Also
# write down one sentence saying why you placed the first one first; the sentence is the part
# that is worth discussing afterwards.
#
# Leaving the list empty is allowed. Stage 2 then skips the comparison.

# %%
MY_RANKING = [
    "",  # 1st
    "",  # 2nd
    "",  # 3rd
    "",  # 4th
]

FOUR = ["logistic regression", "Gaussian naive Bayes", "decision tree", "random forest"]
picked = [m.strip() for m in MY_RANKING if m.strip()]
unknown = [m for m in picked if m not in FOUR]
if not picked:
    print("No prediction recorded. Stage 2 will skip the comparison.")
elif unknown:
    print("Not a model name in the table above:", ", ".join(unknown))
elif len(set(picked)) != len(picked):
    print("A name is repeated. Each model appears once.")
else:
    print("Prediction recorded:")
    for i, m in enumerate(picked, 1):
        print(f"  {i}. {m}")

# %% [markdown]
# ## Stage 2. Rank
#
# ### 2.1 Features
#
# The skewed duration, byte, packet and connection-count columns are log-transformed, every
# numeric column is standardized, and the categorical columns are one-hot encoded. Every step is
# fitted on the training days only. Scaling matters for logistic regression, k-nearest neighbors
# and the support vector machine; it is harmless for the tree models, whose splits depend only on
# the order of the values.

# %%
skewed = ["duration", "src_bytes", "dst_bytes", "packets", "count", "srv_count"]
plain = ["failed_logins", "serror_rate", "rerror_rate", "same_srv_rate", "dst_host_count", "hour"]
categorical = ["protocol", "service", "site"]

prep = ColumnTransformer([
    ("log", make_pipeline(FunctionTransformer(np.log1p, feature_names_out="one-to-one"), StandardScaler()), skewed),
    ("num", StandardScaler(), plain),
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
]).fit(train)

Xtr = prep.transform(train)
Xte = prep.transform(test)
feature_names = [n.split("__", 1)[1] for n in prep.get_feature_names_out()]
print(f"{Xtr.shape[0]:,} training rows and {Xte.shape[0]:,} test rows, {Xtr.shape[1]} features after encoding")

# %% [markdown]
# ### 2.2 Seven classifiers
#
# Every model produces a score for each test record. For the support vector machine the score is
# the value of its decision function; for the others it is a predicted probability. Average
# precision and recall inside a budget depend only on the ordering of the scores, so the two
# kinds of score are comparable.
#
# Models with a random component are trained once per seed, with five seeds. The others are
# deterministic and their standard deviation is zero.
#
# Several models give many records exactly the same score. When the records tied at the cutoff do
# not all fit inside the budget, which of them is alerted is arbitrary, so `recall_at` reports the
# expected recall with ties broken at random.
#
# This cell takes about a minute.

# %%
def make(name, seed):
    return {
        "logistic regression": LogisticRegression(max_iter=10000, tol=1e-8),
        "k-nearest neighbors": KNeighborsClassifier(n_neighbors=25),
        "SVM (RBF kernel)": SVC(kernel="rbf", C=1.0, gamma="scale"),
        "Gaussian naive Bayes": GaussianNB(),
        "decision tree": DecisionTreeClassifier(max_depth=8, random_state=seed),
        "random forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=seed),
        "gradient boosting": HistGradientBoostingClassifier(random_state=seed),
    }[name]


RANDOM = {"decision tree", "random forest", "gradient boosting"}
NAMES = ["logistic regression", "k-nearest neighbors", "SVM (RBF kernel)", "Gaussian naive Bayes",
         "decision tree", "random forest", "gradient boosting"]


def score_of(model, X):
    return model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X)


def recall_at(score, k):
    """Expected recall when the k highest-scoring records are alerted, ties broken at random."""
    cutoff = np.sort(score)[::-1][k - 1]
    above = score > cutoff
    tied = score == cutoff
    alert = above.astype(float)
    alert[tied] = (k - above.sum()) / tied.sum()
    return alert[yte == 1].mean(), alert


rows, scores0, seconds = [], {}, {}
for name in NAMES:
    t0 = time.time()
    for s in (SEEDS if name in RANDOM else [0]):
        model = make(name, s).fit(Xtr, ytr)
        sc = score_of(model, Xte)
        r20, _ = recall_at(sc, 20 * n_days)
        r100, alert = recall_at(sc, 100 * n_days)
        rows.append(dict(model=name, seed=s, ap=average_precision_score(yte, sc),
                         recall20=r20, recall100=r100,
                         **{f"fam_{f}": alert[family == f].mean()
                            for f in ["scan", "bruteforce", "dos", "exfil", "c2beacon"]}))
        if s == 0:
            scores0[name] = sc
    seconds[name] = time.time() - t0

runs = pd.DataFrame(rows)
table = runs.groupby("model", sort=False).agg(ap=("ap", "mean"), ap_sd=("ap", "std"),
                                              recall20=("recall20", "mean"),
                                              recall100=("recall100", "mean")).fillna(0.0)
table["seconds"] = pd.Series(seconds)
print(table.round(3).to_string())

# %% [markdown]
# ### 2.3 How much of that ordering is real
#
# The standard deviation above measures only the randomness inside training. It says nothing
# about how much the scores would change on other test days. A bootstrap over test records gives
# a view of that second source: it resamples the test set with replacement 200 times and
# recomputes average precision each time. Records from the same host and day are not independent,
# so the interval below is narrower than it should be, but it shows which differences are large
# compared with sampling noise.

# %%
rng = np.random.default_rng(0)
boot_idx = [rng.integers(0, len(yte), len(yte)) for _ in range(200)]
boot = {}
for name, sc in scores0.items():
    vals = [average_precision_score(yte[i], sc[i]) for i in boot_idx]
    boot[name] = (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5)))

order = table["ap"].sort_values().index
fig, ax = plt.subplots(figsize=(8, 3.6))
for i, name in enumerate(order):
    lo, hi = boot[name]
    mid = table.loc[name, "ap"]
    ax.plot([lo, hi], [i, i], color="#8a8a8a", lw=2, solid_capstyle="butt")
    ax.plot([mid], [i], "o", color="#bd991f", markeredgecolor="#4a4a4a", markersize=8, zorder=3)
    ax.text(hi + 0.012, i, f"{mid:.3f}  [{lo:.3f}, {hi:.3f}]", va="center", fontsize=8.5)
ax.set_yticks(range(len(order)), order, fontsize=9)
ax.set_xlabel("average precision on the test days, with a 95% bootstrap interval")
ax.set_xlim(0.20, 0.95)
ax.grid(axis="x", alpha=0.3)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
plt.tight_layout()
plt.show()

# %%
measured = [m for m in table["ap"].sort_values(ascending=False).index if m in FOUR]
print("measured order of the four models in stage 1, best first:")
for i, m in enumerate(measured, 1):
    print(f"  {i}. {m:<22} AP {table.loc[m, 'ap']:.3f}   interval [{boot[m][0]:.3f}, {boot[m][1]:.3f}]")

if picked and not unknown and len(set(picked)) == len(picked):
    hits = sum(a == b for a, b in zip(picked, measured))
    print(f"\nyour prediction: {' > '.join(picked)}")
    print(f"positions correct: {hits} of {len(picked)}")
    adjacent = [(a, b) for a, b in zip(picked, picked[1:])
                if boot[a][0] <= boot[b][1] and boot[b][0] <= boot[a][1]]
    for a, b in adjacent:
        print(f"note: the intervals of {a} and {b} overlap, so that one of your"
              f" comparisons cannot be scored either way")
# %% [markdown]
# ### Stage 2 questions
#
# 1. Which parts of the ordering does the figure support, and which does it not? Give one
#    comparison that the intervals leave unresolved.
# 2. The `seconds` column spans two orders of magnitude, and the three random models are fitted
#    once per seed. Describe a deployment in which that ratio decides the choice.
# 3. The interval comes from resampling test records. Which source of variation does it not
#    cover?

# %% [markdown]
# ## Stage 3. Budget
#
# A security team cannot investigate every record it scores. It investigates the highest-scoring
# ones, as many as its staffing allows. That number is the **alert budget**, and it is set by the
# team, not by the model.
#
# The table below repeats the two recall columns from stage 2: recall when the 20 highest-scoring
# records per day are alerted, and when the 100 highest-scoring records per day are alerted.

# %%
budget = pd.DataFrame({
    "AP": table["ap"],
    "recall @ 20/day": table["recall20"],
    "recall @ 100/day": table["recall100"],
}).sort_values("AP", ascending=False)
print(budget.round(3).to_string())

print(f"\ntest period: {n_days} days, {yte.sum()} attacks, {len(test):,} records")
print(f"a budget of  20 alerts per day is {20 * n_days:>3} alerts over the test period")
print(f"a budget of 100 alerts per day is {100 * n_days:>3} alerts over the test period")

fig, ax = plt.subplots(figsize=(8, 3.4))
idx = np.arange(len(budget))
ax.bar(idx - 0.2, budget["recall @ 20/day"], width=0.4, label="20 alerts per day", color="#4a5a6a")
ax.bar(idx + 0.2, budget["recall @ 100/day"], width=0.4, label="100 alerts per day", color="#bd991f")
ax.set_xticks(idx, [n.replace(" (RBF kernel)", "") for n in budget.index], rotation=20, ha="right", fontsize=8.5)
ax.set_ylabel("recall")
ax.legend(frameon=False, fontsize=9)
ax.grid(axis="y", alpha=0.3)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
plt.tight_layout()
plt.show()

# %% [markdown]
# ### Stage 3 questions
#
# 1. Five of the seven models report the same recall at 20 alerts per day. Work out that number
#    from the counts printed above, before running the next cell.
# 2. Account for the tie. Average precision across those five models spans 0.52 to 0.70.
# 3. Five times the budget. How many times the recall? Give the recall bought by one additional
#    alert, above and below the tie.
#
# Write your answers down. The next cell is the answer to question 1 and a measurement for
# question 3.

# %%
ceiling = 20 * n_days / yte.sum()
print(f"a perfect ranking fills {20 * n_days} alerts with attacks, so recall cannot exceed")
print(f"    {20 * n_days} / {yte.sum()} = {ceiling:.3f}")
print(f"models sitting exactly on it: {(np.isclose(table['recall20'], ceiling)).sum()} of {len(table)}")

best_name = table["ap"].idxmax()
sc_best = scores0[best_name]
ks = np.arange(5, 205, 5)
curve = np.array([recall_at(sc_best, int(k * n_days))[0] for k in ks])
cap = np.minimum(1.0, ks * n_days / yte.sum())

fig, ax = plt.subplots(figsize=(8, 3.6))
ax.plot(ks, cap, "--", color="#8a8a8a", lw=1.4, label="ceiling: every alert is an attack")
ax.plot(ks, curve, color="#bd991f", lw=2.2, label=f"{best_name}")
for k in (20, 100):
    r = recall_at(sc_best, int(k * n_days))[0]
    ax.plot([k], [r], "o", color="#4a5a6a", zorder=3)
    ax.annotate(f"{k}/day\nrecall {r:.3f}", (k, r), textcoords="offset points", xytext=(8, -14), fontsize=8.5)
ax.set_xlabel("alert budget, alerts per day")
ax.set_ylabel("recall over the test period")
ax.set_ylim(0, 1.02)
ax.legend(frameon=False, fontsize=9, loc="lower right")
ax.grid(alpha=0.3)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
plt.tight_layout()
plt.show()

r20 = recall_at(sc_best, 20 * n_days)[0]
r100 = recall_at(sc_best, 100 * n_days)[0]
extra = 100 * n_days - 20 * n_days
print(f"{best_name}: recall {r20:.3f} at 20 per day, {r100:.3f} at 100 per day, a factor of {r100 / r20:.2f}")
print(f"below the ceiling every alert is an attack and buys 1/{yte.sum()} = {1 / yte.sum():.4f} recall")
print(f"the {extra} additional alerts buy {(r100 - r20) / extra:.4f} recall each, "
      f"which is {(r100 - r20) / extra * yte.sum():.0%} of that")
print(f"their precision is {(r100 - r20) * yte.sum() / extra:.3f}")

# %% [markdown]
# ## Stage 4. Family
#
# An aggregate score over all attacks hides which attacks are caught. The table below gives, for
# each model, the share of each family's test records that fall inside a budget of 100 alerts per
# day.

# %%
fam_table = runs.groupby("model", sort=False)[[c for c in runs.columns if c.startswith("fam_")]].mean()
fam_table.columns = [c[4:] for c in fam_table.columns]
fam_table = fam_table.loc[table["ap"].sort_values(ascending=False).index]
print(fam_table.round(2).to_string())

counts = pd.Series(family).value_counts()
print("\nattacks in the test period by family:")
for f in fam_table.columns:
    print(f"  {f:<12} {counts.get(f, 0):>4}   {counts.get(f, 0) / yte.sum():.0%} of all test attacks")

fig, ax = plt.subplots(figsize=(7.2, 3.4))
im = ax.imshow(fam_table.to_numpy(), cmap="YlGnBu", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(fam_table.shape[1]), fam_table.columns, fontsize=9)
ax.set_yticks(range(fam_table.shape[0]), [n.replace(" (RBF kernel)", "") for n in fam_table.index], fontsize=9)
for i in range(fam_table.shape[0]):
    for j in range(fam_table.shape[1]):
        v = fam_table.iat[i, j]
        ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=8.5,
                color="white" if v > 0.55 else "#252b33")
ax.set_title("recall by attack family, budget of 100 alerts per day", fontsize=10)
fig.colorbar(im, ax=ax, shrink=0.85)
plt.tight_layout()
plt.show()

# %% [markdown]
# ### Stage 4 questions
#
# One family is close to zero for every one of the seven models, and it is the largest family in
# the test period. Two explanations are available, and they call for different responses.
#
# **A. The information is not in the features.** Every column here describes a single connection.
# If what distinguishes this family is a pattern across many connections, no model fitted on
# these columns can recover it, and the response is to collect a different feature.
#
# **B. The class is not in the training labels.** A supervised model estimates a boundary between
# the classes it was shown. If this family never appears in the training days, the model was never
# asked to separate it from normal traffic, and the response is a labelling and retraining problem.
#
# Before running the next cell: which measurement would distinguish A from B?

# %%
fam_period = pd.crosstab(flows["attack_type"], np.where(flows["day"] <= 9, "training days", "test days"))
print(fam_period.loc[[f for f in fam_table.columns]].to_string())

target = "c2beacon"
sub = test[(test["attack_type"] == target) | (test["label"] == 0)].copy()
y_sub = (sub["attack_type"] == target).astype(int).to_numpy()
pipe = make_pipeline(
    ColumnTransformer([
        ("log", make_pipeline(FunctionTransformer(np.log1p, feature_names_out="one-to-one"), StandardScaler()), skewed),
        ("num", StandardScaler(), plain),
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
    ]),
    RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=0),
)
cv = cross_val_score(pipe, sub[skewed + plain + categorical], y_sub,
                     cv=StratifiedKFold(5, shuffle=True, random_state=0), scoring="average_precision")

print(f"\nSame features, same model, {target} records labelled and present in training:")
print(f"    average precision {cv.mean():.3f} (5-fold, sd {cv.std():.3f}), base rate {y_sub.mean():.2%}")
print(f"In stage 2, trained on days 0 to 9 where {target} does not occur:")
for n in fam_table.index:
    print(f"    {n:<22} recall {fam_table.loc[n, target]:.2f}")

# %% [markdown]
# ### What that measurement shows
#
# The features separate this family well once the family is labelled in the training data:
# average precision around 0.8 at a base rate under 2 per cent. The failure in stage 2 is
# therefore explanation **B**. The detector was never shown the class, so it never learned a
# boundary around it, and no choice of classifier or threshold repairs that.
#
# Two consequences worth stating precisely.
#
# 1. The number reported in stage 2 is not an estimate of performance on next week's traffic.
#    It is an estimate of performance on next week's traffic **assuming the same attack families
#    in the same proportions**. That assumption failed inside a fourteen-day window of synthetic
#    data built for a course.
# 2. A detector cannot tell you that this happened. Nothing in the output of stage 2 announces a
#    new family; the recall column simply went down.
#
# **Open questions.**
#
# - What would make a new family visible, given that the detector will not report it?
# - The usual answer is unsupervised anomaly detection, which requires no labels. Lab 4 of the
#   same course measures it on this family: isolation forest recall 0.0, one-class SVM 0.0, local
#   outlier factor 0.13. Separable with labels, and not an outlier without them. Why would both
#   be true at once?
# - Beaconing in a real network is identified by the regularity of a host's connections over
#   hours. No column here measures anything across connections. What would that feature cost to
#   collect, and what delay would it add to detection?
# %% [markdown]
# ## Stage 5. Extras
#
# Three items, harder than stages 1 to 4, for pairs that reach this point. Each is one cell.

# %% [markdown]
# ### 5a. Two measures of feature importance
#
# A column of pure noise is added to the data and the forest is trained again. The column is
# random, so it carries no information about the label. Two importance measures are computed for
# it:
#
# - **impurity importance**, the total decrease in Gini impurity produced by splits on the column,
#   averaged over trees, computed on the training data;
# - **permutation importance**, the average precision lost on the test data when the column is
#   shuffled.
#
# Which of the two would you put in a report, and what is the other one measuring?

# %%
noise_rng = np.random.default_rng(1)
Xtr_n = np.hstack([Xtr, noise_rng.normal(size=(len(Xtr), 1))])
Xte_n = np.hstack([Xte, noise_rng.normal(size=(len(Xte), 1))])
names_n = feature_names + ["noise"]

rf_noise = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=0).fit(Xtr_n, ytr)
imp_impurity = pd.Series(rf_noise.feature_importances_, index=names_n)
pi_n = permutation_importance(rf_noise, Xte_n, yte, scoring="average_precision", n_repeats=5, random_state=0)
imp_perm = pd.Series(pi_n.importances_mean, index=names_n)

compare = pd.DataFrame({"impurity": imp_impurity, "permutation": imp_perm}).sort_values("impurity", ascending=False)
noise_rank = int((imp_impurity > imp_impurity["noise"]).sum()) + 1
print(compare.head(12).round(4).to_string())
print(f"\nnoise column: impurity {imp_impurity['noise']:.4f}, rank {noise_rank} of {len(names_n)};"
      f" permutation {imp_perm['noise']:.4f}")

top = compare.head(12).iloc[::-1]
pos = np.arange(len(top))
fig, ax = plt.subplots(figsize=(8, 4))
ax.barh(pos - 0.2, top["impurity"], height=0.4, color="#4a5a6a", label="impurity, training data")
ax.barh(pos + 0.2, top["permutation"], height=0.4, color="#bd991f", label="permutation, test data")
ax.set_yticks(pos, top.index, fontsize=9)
for lab in ax.get_yticklabels():
    if lab.get_text() == "noise":
        lab.set_color("#b03a2e")
        lab.set_fontweight("bold")
ax.set_xlabel("importance")
ax.legend(frameon=False, fontsize=9)
ax.grid(axis="x", alpha=0.3)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
plt.tight_layout()
plt.show()

# %% [markdown]
# ### 5b. Underfitting and overfitting
#
# The depth of a decision tree controls how complex it can be. Trees of increasing depth are
# trained and scored on the training days and on the test days.
#
# The curve has a maximum. Selecting the depth at that maximum from this plot is a methodological
# error. Name it, and say what should be done instead.

# %%
depths = list(range(1, 21))
depth_train, depth_test = [], []
for d in depths:
    tree = DecisionTreeClassifier(max_depth=d, random_state=0).fit(Xtr, ytr)
    depth_train.append(average_precision_score(ytr, tree.predict_proba(Xtr)[:, 1]))
    depth_test.append(average_precision_score(yte, tree.predict_proba(Xte)[:, 1]))

best_depth = depths[int(np.argmax(depth_test))]
fig, ax = plt.subplots(figsize=(8, 3.6))
ax.plot(depths, depth_train, "o-", color="#4a5a6a", ms=4, label="training days")
ax.plot(depths, depth_test, "o-", color="#bd991f", ms=4, label="test days")
ax.axvline(best_depth, color="#b03a2e", ls="--", lw=1.2)
ax.annotate(f"highest test AP at depth {best_depth}", (best_depth, max(depth_test)),
            textcoords="offset points", xytext=(10, -4), fontsize=9, color="#b03a2e")
ax.set_xlabel("maximum depth of the tree")
ax.set_ylabel("average precision")
ax.set_xticks(depths[::2])
ax.set_ylim(0, 1.05)
ax.legend(frameon=False, fontsize=9)
ax.grid(alpha=0.3)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
plt.tight_layout()
plt.show()

print(f"depth  1: train {depth_train[0]:.3f}  test {depth_test[0]:.3f}")
print(f"depth {best_depth:2d}: train {depth_train[best_depth - 1]:.3f}  test {depth_test[best_depth - 1]:.3f}")
print(f"depth 20: train {depth_train[-1]:.3f}  test {depth_test[-1]:.3f}")

# %% [markdown]
# ### 5c. Decision boundaries
#
# Four models are trained on two features only, so that the boundary each draws can be seen:
# `log(1 + count)` and `serror_rate`, the share of connections with SYN errors. The shading is the
# predicted probability of an attack over a grid. Black points are attacks, white points are
# normal records.
#
# The lecture showed six models on these same two features. Two questions here.
#
# One of the four shapes below is not supported by the data: which, and why does that model draw
# it at all? And the lecture's random forest panel is this tree's shape at a finer grain: what
# would this panel look like at depth 12 instead of 4, and what does 5b say about doing that?

# %%
def two_features(df):
    return np.column_stack([np.log1p(df["count"].to_numpy()), df["serror_rate"].to_numpy()])


Z_tr = two_features(train)
scaler2 = StandardScaler().fit(Z_tr)
g0 = np.linspace(0, np.log1p(train["count"].max()) * 1.02, 80)
g1 = np.linspace(0, 1, 80)
G0, G1 = np.meshgrid(g0, g1)
grid = scaler2.transform(np.column_stack([G0.ravel(), G1.ravel()]))

boundary_models = {
    "k-nearest neighbors (k=25)": KNeighborsClassifier(n_neighbors=25),
    "SVM (RBF kernel)": SVC(kernel="rbf", C=1.0, gamma="scale", probability=True, random_state=0),
    "Gaussian naive Bayes": GaussianNB(),
    "decision tree (depth 4)": DecisionTreeClassifier(max_depth=4, random_state=0),
}
sub_idx = np.random.default_rng(0).choice(len(Z_tr), 6000, replace=False)
fig, axes = plt.subplots(1, 4, figsize=(16, 3.8), sharey=True)
for ax, (name, m) in zip(axes, boundary_models.items()):
    m.fit(scaler2.transform(Z_tr[sub_idx]), ytr[sub_idx])
    P = m.predict_proba(grid)[:, 1].reshape(G0.shape)
    ax.contourf(G0, G1, P, levels=np.linspace(0, 1, 11), cmap="RdBu_r", alpha=0.7)
    pts = sub_idx[:1500]
    ax.scatter(Z_tr[pts, 0], Z_tr[pts, 1], c=np.where(ytr[pts] == 1, "k", "w"), s=6,
               edgecolors="k", linewidths=0.2)
    ax.set_title(name, fontsize=10)
    ax.set_xlabel("log(1 + count)")
axes[0].set_ylabel("serror_rate")
plt.tight_layout()
plt.show()

# %% [markdown]
# ### 5d. One number to change
#
# `K_NEIGHBORS` is the number of neighbours k-nearest neighbors votes over. It is 25 in stage 2.
# Set it to 1, run the cell, then set it to 200 and run it again.
#
# Predict the direction of the change in average precision before each run, and account for what
# you see. A score produced by k = 1 can take only two values.

# %%
K_NEIGHBORS = 25

knn = KNeighborsClassifier(n_neighbors=K_NEIGHBORS).fit(Xtr, ytr)
sc_knn = knn.predict_proba(Xte)[:, 1]
print(f"k = {K_NEIGHBORS}")
print(f"  average precision   {average_precision_score(yte, sc_knn):.3f}   (k = 25 in stage 2: {table.loc['k-nearest neighbors', 'ap']:.3f})")
print(f"  recall @ 100/day    {recall_at(sc_knn, 100 * n_days)[0]:.3f}")
print(f"  distinct score values {len(np.unique(sc_knn))}")

# %% [markdown]
# ## Close
#
# What this activity measured, in order:
#
# 1. A ranking of seven models, and how much of that ranking survives its own uncertainty.
# 2. An operating point at which five of the seven are indistinguishable, because the alert
#    budget and not the model determines recall there.
# 3. A family of attacks that no model detects, and a measurement showing the cause is the
#    absence of the class from the training labels rather than the absence of information from
#    the features.
#
# Optional, same dataset, same pattern, in the same course:
#
# - **Lab 4, anomaly detection.** Unsupervised methods on this family: isolation forest 0.0,
#   one-class SVM 0.0, local outlier factor 0.13.
# - **Lab 2, leakage.** The same model and the same records score 0.86 under a random split and
#   0.52 under a time-ordered split.
# - **Lab 11, audit.** Per-site error rates with intervals, and a generated model card.
#
# <https://aalbata.github.io/machine-learning-for-cybersecurity/>
