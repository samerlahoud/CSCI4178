# %% [markdown]
# # CSCI 4178: Comparing Security Detectors
#
# **Work in pairs. About 30 minutes. No ML background or Python editing required.**
#
# Your job is to decide what the results mean for a security team. The code is supplied.
# Keep your answers on paper or in a separate document. Nothing needs to be typed into code.
#
# **First time in Colab?** Sign in to Google, then click **Connect** if needed. Use the default CPU runtime.
# Click the triangular **play button** beside a code cell. Wait until it finishes before running the next cell.
# If Colab warns that this notebook was authored elsewhere, check that it is the course notebook linked by your instructor before running it.
# A spinner means it is still working. You do not need to understand the Python underneath.
#
# **Run one stage at a time.** Stop at each **PAUSE** before revealing the next result. Do not use *Run all*.
#
# | Stage | Time | Your task |
# | --- | --- | --- |
# | 0. Setup | 2 min | Run one cell to load the data. |
# | 1. Predict | 2 min | Choose a model and give a reason. |
# | 2. Compare | 8 min | Read the ranking and uncertainty bars. |
# | 3. Budget | 8 min | Explain why different models can tie. |
# | 4. Missing family | 10 min | Investigate a shared blind spot. |
# | 5. Optional | Spare time | Choose one extra. Run supplied cells only. |
#
# **The data is synthetic:** simulated connection records over 14 days at two sites.
# A row is one connection, not a whole incident. These results illustrate evaluation methods, not a product recommendation.
#
# Derived from **Lab 3a, Comparing classifiers on a time-ordered split**, in
# [Machine Learning for Cybersecurity](https://aalbata.github.io/machine-learning-for-cybersecurity/)
# by Ali Al Bataineh. Course text CC BY 4.0, code MIT. The data version is fixed for this activity.

# %% [markdown]
# ## Stage 0. Setup (2 minutes)
#
# **RUN** the next cell once. It loads the data automatically. No upload, install command or GPU is needed in Colab.
#
# **LOOK FOR** two lines: training days **0–9**, test days **10–13**.
# Training means learning from old examples. Testing means checking against later examples whose answers were hidden during training.
# Exact duplicate rows are removed before splitting.
#
# **CHECK** You should see **432 attacks in the test period**. If there is a red error, stop and ask for help.
# If a later cell says a name is undefined, run the earlier cells in order. If the runtime disconnected, reconnect and repeat the completed stages.
# If setup is still blocked after two minutes, work with your partner or use the supplied results handout.

# %%
import os
import time
import warnings
from pathlib import Path

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



URL = "https://raw.githubusercontent.com/aalbata/machine-learning-for-cybersecurity/009634e4f6e414550e79ca704a3164020abd9b03/data/flows.csv"
source = os.environ.get("L14_DATA_PATH", URL)
try:
    flows = pd.read_csv(source).drop_duplicates().reset_index(drop=True)
except Exception as exc:
    raise RuntimeError("Could not load the course data. Check the connection or use the results handout.") from exc

train = flows[flows["day"] <= 9]
test = flows[flows["day"] >= 10]
ytr = train["label"].to_numpy()
yte = test["label"].to_numpy()
family = test["attack_type"].to_numpy()
n_days = test["day"].nunique()
test_days = test["day"].to_numpy()

print(f"training  days 0-9    {len(train):>7,} records   {ytr.sum():>4} attacks")
print(f"test      days 10-13  {len(test):>7,} records   {yte.sum():>4} attacks   over {n_days} days")
print(f"attack rate: training {ytr.mean():.3%}, test {yte.mean():.3%}")
print("Setup complete. Go to Stage 1; write your prediction on paper.")

# %% [markdown]
# ## Stage 1. Predict (2 minutes, no code cell)
#
# | Model | Intuition |
# | --- | --- |
# | Logistic regression | Adds weighted features into one score. |
# | Gaussian naive Bayes | Combines how typical each feature is for each class. |
# | Decision tree | Asks a sequence of yes/no questions. |
# | Random forest | Averages the opinions of many trees. |
#
# **WRITE** which one you expect to rank attacks highest, and one reason. If you wish, rank all four.
# There is no correct prediction to memorise. We will compare your expectation with measurements.
#
# **Metric key for the rest of the activity**
#
# - **Average precision (AP):** how well attacks concentrate near the top of the ranked list across many cutoffs. Higher is better, up to 1. It is **not accuracy** or recall at one alert budget.
# - **Recall:** the fraction of actual attack records that receive an alert. Recall 0.60 means about 60 of every 100 attack records were flagged.
# - **Precision:** the fraction of alerts that are actual attacks. Precision 0.60 means about 60 of every 100 alerts are correct.
# - **Budget:** the number of records the team can investigate **each day**.
#
# Imagine reading a queue from the top: good ranking puts attacks early. The budget tells you where you must stop reading.

# %% [markdown]
# ## Stage 2. Compare the detectors (8 minutes)
#
# ### 2.1 Prepare the measurements
#
# **RUN** the next cell. It converts the recorded features into numbers the models can use.
# It learns the conversion from training data only. A feature is a single recorded measurement, such as bytes sent or failed logins.
#
# **LOOK FOR** the number of training rows, test rows and encoded features. You do not need to interpret the transformation code.

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
# ### 2.2 Train and compare
#
# **RUN** the next cell. It may take a minute or more. A line appears as each model finishes.
# Each model sees the same training records and gets scored on the same later records.
# We use one fixed random seed to keep the classroom comparison reproducible.
#
# **READ** the table by columns:
#
# | Column | Meaning |
# | --- | --- |
# | `ap` | Ranking quality. Start here. Higher is better. |
# | `recall20`, `recall100` | Share of attacks found at 20 or 100 alerts **each day**. We use these in stage 3. |
# | `fit_seconds` | Time to learn from the training examples. |
# | `predict_seconds` | Time to score all test records. |
#
# **WRITE** the model with the highest AP. Did it match your prediction?
# Times depend on the machine, so compare them within your run.
#
# Technical detail, optional: scores need only order records. They are not necessarily calibrated probabilities.
# If scores tie at the daily cutoff, the notebook averages over random choices among those tied records.

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


NAMES = ["logistic regression", "k-nearest neighbors", "SVM (RBF kernel)", "Gaussian naive Bayes",
         "decision tree", "random forest", "gradient boosting"]
FOUR = ["logistic regression", "Gaussian naive Bayes", "decision tree", "random forest"]


def score_of(model, X):
    return model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X)


def daily_alert_weights(score, days, k):
    """Exactly min(k, available records) slots per day, fractional weights for random ties."""
    score, days = np.asarray(score), np.asarray(days)
    if len(score) != len(days) or int(k) != k or k < 0:
        raise ValueError("Scores and days must align; k must be a nonnegative integer.")
    alert = np.zeros(len(score), dtype=float)
    for day in np.unique(days):
        idx = np.flatnonzero(days == day)
        slots = min(int(k), len(idx))
        if slots == 0:
            continue
        values = score[idx]
        cutoff = np.sort(values)[-slots]
        above, tied = values > cutoff, values == cutoff
        weights = above.astype(float)
        weights[tied] = (slots - above.sum()) / tied.sum()
        alert[idx] = weights
    return alert


def recall_at(score, k):
    alert = daily_alert_weights(score, test_days, k)
    return float(alert[yte == 1].mean()), alert


rows, scores0 = [], {}
for name in NAMES:
    t0 = time.perf_counter()
    model = make(name, 0).fit(Xtr, ytr)
    fit_time = time.perf_counter() - t0
    t0 = time.perf_counter()
    sc = score_of(model, Xte)
    predict_time = time.perf_counter() - t0
    r20, _ = recall_at(sc, 20)
    r100, alert = recall_at(sc, 100)
    rows.append(dict(model=name, ap=average_precision_score(yte, sc),
                     recall20=r20, recall100=r100,
                     fit_seconds=fit_time, predict_seconds=predict_time,
                     **{f"fam_{f}": alert[family == f].mean()
                        for f in ["scan", "bruteforce", "dos", "exfil", "c2beacon"]}))
    scores0[name] = sc
    print(f"Finished: {name}", flush=True)

runs = pd.DataFrame(rows)
table = runs.set_index("model")[["ap", "recall20", "recall100", "fit_seconds", "predict_seconds"]]
print("\nComparison (one fixed seed, same split):")
print(table.sort_values("ap", ascending=False).round(3).to_string())

# %% [markdown]
# ### 2.3 How much should we trust a small gap?
#
# **RUN** the next two cells. The dot is a model's AP. The horizontal bar shows how that AP varies when we repeatedly resample these same test records.
# This is called a **bootstrap interval**. It helps us see sampling uncertainty without doing the statistics by hand.
#
# **LOOK FOR** a pair of bars that overlap. Their point scores differ, but this picture alone is not enough to make a confident claim about the difference.
# Overlapping bars do not prove the models are equivalent. A formal comparison would analyse their paired score differences.
#
# These bars reuse the same four days. They do **not** tell us how well the models will work at a different site or next month.
# Related records can also make these simple intervals too optimistic.

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
print("Compare this measured order with your written prediction.")

# %% [markdown]
# ### PAUSE 2: Write three short answers
#
# 1. Which model has the highest measured AP? Name one pair whose uncertainty bars overlap.
# 2. A detector scores traffic continuously but retrains only at night. Which timing column matters most while it is running?
# 3. Do these bars establish performance on a new network? Answer yes/no and explain in one sentence.
#
# **Move on when you can explain one row of the table to your partner.**

# %% [markdown]
# ## Stage 3. The team's alert budget (8 minutes)
#
# The team investigates the **20 highest-scoring records each day**, or the **100 highest each day** if more staff are available.
# It cannot carry unused capacity from one day into another. The notebook applies the cutoff separately to each day.
#
# **RUN** the next cell. Read the two recall columns and the counts under the table.
#
# **LOOK FOR** several models tied near 0.185 at the smaller budget. AP considers the wider ranking, while this budget inspects only its top few records.

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
# ### PAUSE 3: Before the answer cell
#
# 1. Four days at 20 alerts per day allow at most **___ alerts**. There are **432 attack records**.
#    Even if every alert catches an attack, recall can be at most **___ / 432 = ___**.
# 2. If several models fill every available slot with an attack, can a better ranking make them catch more attacks without more slots?
# 3. Predict: will five times as many alerts necessarily catch five times as many attacks?
#
# **HINT:** 0.185 means 18.5%, not 0.185%.
#
# **NOW RUN** the next cell to check. The dashed line is the ideal upper bound. The solid line is the measured model.
# After seeing the result, complete: “Increasing the budget also brings in more ___.”

# %%
ceiling = 20 * n_days / yte.sum()
print(f"For this dataset, each day has at least 20 attacks. A perfect ranking fills {20 * n_days} alerts with attacks, so recall cannot exceed")
print(f"    {20 * n_days} / {yte.sum()} = {ceiling:.3f}")
print(f"models sitting exactly on it: {(np.isclose(table['recall20'], ceiling)).sum()} of {len(table)}")

best_name = table["ap"].idxmax()
sc_best = scores0[best_name]
ks = np.arange(5, 205, 5)
curve = np.array([recall_at(sc_best, int(k))[0] for k in ks])
attacks_per_day = np.array([yte[test_days == day].sum() for day in np.unique(test_days)])
cap = np.array([np.minimum(k, attacks_per_day).sum() / yte.sum() for k in ks])

fig, ax = plt.subplots(figsize=(8, 3.6))
ax.plot(ks, cap, "--", color="#8a8a8a", lw=1.4, label="ceiling: every alert is an attack")
ax.plot(ks, curve, color="#bd991f", lw=2.2, label=f"{best_name}")
for k in (20, 100):
    r = recall_at(sc_best, int(k))[0]
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

r20 = recall_at(sc_best, 20)[0]
r100 = recall_at(sc_best, 100)[0]
extra = 100 * n_days - 20 * n_days
print(f"{best_name}: recall {r20:.3f} at 20 per day, {r100:.3f} at 100 per day, a factor of {r100 / r20:.2f}")
print(f"while every selected record is an attack, each alert adds 1/{yte.sum()} = {1 / yte.sum():.4f} recall")
print(f"the {extra} additional alerts buy {(r100 - r20) / extra:.4f} recall each, "
      f"which is {(r100 - r20) / extra * yte.sum():.0%} of that")
print(f"their precision is {(r100 - r20) * yte.sum() / extra:.3f}")

# %% [markdown]
# ## Stage 4. A shared blind spot (10 minutes)
#
# An overall score can hide a family of attacks. **RUN** the next cell and read each column as one family.
# Each value is the fraction of that family's attack records caught at **100 alerts per day**.
#
# | Family | Plain-language meaning |
# | --- | --- |
# | `scan` | Probing hosts or services |
# | `bruteforce` | Repeated login guesses |
# | `dos` | Traffic intended to disrupt service |
# | `exfil` | Sending data out |
# | `c2beacon` | An infected device checking in with a command-and-control server |
#
# **WRITE** the family with low recall across all models and how many of the 432 attacks it represents.
# A value near zero means few were caught. It does not mean the family was absent from the test data.

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
# ### PAUSE 4: Two possible explanations
#
# **A. Missing features:** the recorded measurements do not distinguish this family from normal traffic.
# We may need extra information, such as repeated connections from the same host over time.
#
# **B. Missing training examples:** the training period contains no labelled examples of this family.
# The measurements might help if the learner gets relevant examples.
#
# **DISCUSS** these two checks before running the next cell:
#
# 1. Count this family in training and test. What would a zero in training tell us?
# 2. As a diagnostic only, let a model learn from some labelled examples of the missed family, then test on other examples from that period. If ranking improves, what does that suggest about A?
#
# **WRITE** your prediction, then **RUN** the next cell.
# It splits the later records into five groups, learns from four and scores the held-out group in turn.
# This is a diagnostic after inspecting the failure, not a new forecast of performance on future days.

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

print(f"\nDiagnostic only: same features and forest, {target} versus normal within the later period:")
print(f"    average precision {cv.mean():.3f} (5-fold, sd {cv.std():.3f}), base rate {y_sub.mean():.2%}")
print(f"In stage 2, trained on days 0 to 9 where {target} does not occur:")
for n in fam_table.index:
    print(f"    {n:<22} recall {fam_table.loc[n, target]:.2f}")

# %% [markdown]
# ### Reading the diagnosis
#
# The family has **0 training examples** and **180 test examples**.
# With labelled examples of this family, the same feature set supports much better ranking in the diagnostic experiment.
# This supports **B as an important explanation here**. The features do carry useful information.
#
# The diagnostic also changes the task: it compares this family with normal traffic within the later period.
# It does **not** prove that missing labels are the only cause, or that retraining would reach this AP on future days.
# An unseen family can sometimes be detected if it shares features with known attacks. There is no guarantee either way.
#
# **WRITE your recommendation:**
# “Before deploying, I would collect ___, test on ___, and monitor ___.”
#
# **Suggested direction:** collect independently investigated examples of missed attacks, evaluate on later untouched days, and monitor misses by family as well as total alerts.
#
# **DISCUSS:** how could you discover a missed family? Consider incident reports, another detector, or investigation of a sample of unflagged traffic.
# A low alert count alone does not establish that the network is safe.

# %% [markdown]
# ## Stage 5. Optional extras
#
# Choose **one** if you finish early. All code is supplied, including the comparison of different neighbour counts.
# No edits are needed. The core activity ends at stage 4.

# %% [markdown]
# ### 5a. Which features actually help?
#
# **RUN** the next cell. It adds a random noise column and measures “importance” in two ways.
#
# - **Impurity importance:** how much the forest used a column to separate training examples.
# - **Permutation importance:** how much held-out AP drops when the column's values are shuffled.
#
# **WRITE:** a noise column can help a model memorise training data. Which measure is better evidence of usefulness on held-out records?
# Read the printed noise row. The two scales differ, so compare the interpretation rather than the bar lengths directly.
# Neither measure proves causation. Correlated features can also hide each other's usefulness.

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
# ### 5b. Learning patterns or memorising examples?
#
# **RUN** the next cell. A deeper tree can ask more questions.
# The training curve shows performance on familiar examples. The test curve shows performance on later examples.
#
# **LOOK FOR:** training performance keeps improving while test performance eventually gets worse.
# That is **overfitting**: learning details that do not carry over.
#
# **WRITE:** why would choosing the best depth from this test graph make the test less trustworthy?
# **HINT:** a final exam stops being an independent exam if you use its answers to choose what to learn.
# Use separate validation days for model choices, then evaluate on untouched test days.

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
# ### 5c. What shape does each model draw?
#
# **RUN** the next cell. To make a picture possible, models use just two features here.
# Black points are attacks, white points are normal records. Red shading means a higher attack score.
#
# **MATCH:** which model makes rectangular steps? Which follows nearby examples? Which makes smooth curves?
# Use the lecture reference table. Explain one match to your partner.
#
# A two-feature picture helps explain a mechanism. It does not explain the entire model's score with all features.

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
# ### 5d. One neighbour or many?
#
# **PREDICT** whether one neighbour will give a more or less detailed ranking than 25 neighbours.
# Then **RUN** the next cell once. It compares **k = 1, 25 and 200** automatically.
#
# **LOOK FOR** the number of distinct scores. With one neighbour the vote is only 0 or 1, creating many ties.
# More neighbours allow more score levels but may smooth away useful local patterns.
#
# **WRITE** one reason why more neighbours need not always improve AP.

# %%
for k in [1, 25, 200]:
    knn = KNeighborsClassifier(n_neighbors=k).fit(Xtr, ytr)
    sc_knn = knn.predict_proba(Xte)[:, 1]
    print(f"k = {k:3d} | AP {average_precision_score(yte, sc_knn):.3f} | "
          f"recall @ 100/day {recall_at(sc_knn, 100)[0]:.3f} | "
          f"distinct scores {len(np.unique(sc_knn))}")

# %% [markdown]
# ## Your four-line report
#
# 1. **Ranking:** the highest measured AP was ___; a small gap deserves caution because ___.
# 2. **Capacity:** at 20 alerts/day, the recall upper bound is ___; the limit comes from ___.
# 3. **Coverage:** ___ was often missed; the diagnostic suggests ___.
# 4. **Next step:** before deployment, I would ___.
#
# If you can explain these four lines without reading the code, you have completed the activity.
#
# Optional follow-up: [Machine Learning for Cybersecurity](https://aalbata.github.io/machine-learning-for-cybersecurity/),
# Lab 4 on anomaly detection, Lab 2 on evaluation leakage, or Lab 11 on auditing errors.
# These source labs are more technical. Reading their explanations and outputs is sufficient.

