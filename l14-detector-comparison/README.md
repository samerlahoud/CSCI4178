# L14 activity, detector comparison

The in-class notebook for **Tuesday November 24, CSCI 4178**. Five stages, 30 minutes, pairs.
Students write no Python: they run cells in order and read the output. One cell in stage 5 asks
for a single number to be changed.

| File | Use |
| --- | --- |
| `L14-detector-comparison.ipynb` | The notebook handed to students. |
| `L14-detector-comparison.py` | The same content in percent format, for editing and for running outside a notebook. |

Answers are in `Lectures/fall-26/L14-teaching-guide.md`, not here, so the file can be handed out
as it is.

## Getting it in front of students

The notebook has no local dependency. It fetches `flows.csv` over HTTPS from the source course's
repository, so there is nothing to clone, mount or upload besides the notebook itself.

Push it to a public GitHub repository and students open it in one click:

```
colab.research.google.com/github/<owner>/<repo>/blob/<branch>/<path>.ipynb
```

Slide 22 of the deck currently prints:

```
colab.research.google.com/github/samerlahoud/detector-comparison/blob/main/L14-detector-comparison.ipynb
```

so that link assumes a public repository `samerlahoud/detector-comparison` holding this notebook at
the root of `main`. Any other owner, repository, branch or path means one edit to slide 22. Post
the same link on Brightspace, since a URL read off a projector is the most likely thing to go
wrong. Colab's *File, Upload notebook* also accepts the `.ipynb` directly, which is the fallback
for a student whose network blocks GitHub.

A Google account is required either way. Announce that the day before.

## Runtime

About 30 seconds of compute on a laptop CPU, and under two minutes on a Colab CPU runtime. No GPU.
The heaviest cells are the seven-model comparison in stage 2 and the permutation importance in
stage 5a.

## Verified figures

Run on November 23 2026, scikit-learn 1.6.1. Colab may differ in the third decimal; no conclusion
in the activity depends on that.

| Measurement | Value |
| --- | --- |
| Random forest, average precision | 0.700, bootstrap interval [0.651, 0.729] |
| Gradient boosting | 0.641, [0.603, 0.682] |
| Gaussian naive Bayes | 0.310, [0.268, 0.351] |
| Recall ceiling at 20 alerts per day | 80 / 432 = 0.185, reached exactly by five of seven models |
| Random forest at 100 alerts per day | 0.606 |
| `c2beacon` in the training days | 0 records, against 180 in the test days |
| `c2beacon` recall, every model | 0.00 to 0.08 |
| `c2beacon` average precision when it is labelled in training | 0.823, base rate 1.76 per cent |
| Noise column | impurity importance 0.016, rank 14 of 25; permutation importance 0.0004 |
| Decision tree | best test AP 0.520 at depth 6; depth 20 reaches 1.000 on training and 0.458 on test |

## Source

Derived from **Lab 3a, *Comparing classifiers on a time-ordered split***, in *Machine Learning for
Cybersecurity* by Ali Al Bataineh, <https://aalbata.github.io/machine-learning-for-cybersecurity/>.
Course text CC BY 4.0, code MIT. The preprocessing, the seven model definitions, the tie-aware
`recall_at`, the bootstrap, the importance comparison, the depth sweep and the boundary plot are
from that lab. The staging, the figures in stages 2 to 4, and the experiment that identifies the
cause of the `c2beacon` failure are written for this course.
