# L14: Comparing security detectors

You can work in pairs.
**No Python writing or editing, including optional exercises.** You can simply run supplied cells and write your answers in a separate document.

## Files

| File | Use |
| --- | --- |
| `L14-detector-comparison.ipynb` | Guided student notebook for Colab or Jupyter |
| `L14-detector-comparison-results.html` | Offline alternative with the same prompts and saved results, without code |
| `L14-detector-comparison.py` | Matching percent-format source for instructor maintenance |

The results handout opens in any browser. Stage 3 and 4 answers are behind **Reveal** controls so you can think first. It requires no Python, Google account or network connection. Its recorded timings are examples from one local machine.

## Opening the notebook

Use the instructor's Colab link, sign in to Google, and click **Connect** if needed. Use the default CPU runtime. Click the triangular play button beside each code cell and wait for it to finish. **Do not use Run all**: stop at the PAUSE prompts before revealing answers.

Click here to [Open in Colab](https://colab.research.google.com/github/samerlahoud/CSCI4178/blob/main/l14-detector-comparison/L14-detector-comparison.ipynb).

The notebook fetches its synthetic dataset automatically; there is no Drive mount, data upload or GPU requirement.

If a cell displays an undefined-name error, run earlier cells in order. If setup stays blocked, share a working laptop or use the offline results handout.

## Activity path

1. Load the data (2 minutes).
2. Predict which familiar model will rank attacks best (2 minutes).
3. Compare ranking, uncertainty and timing (8 minutes).
4. Explain the daily alert-budget limit (8 minutes).
5. Investigate a family the models often miss, then recommend a next step (10 minutes).

Optional stage 5 explores feature importance, overfitting, boundary shapes or neighbour counts. Choose one. Every comparison is already coded.

## Source and attribution

Derived from **Lab 3a, Comparing classifiers on a time-ordered split**, in [Machine Learning for Cybersecurity](https://aalbata.github.io/machine-learning-for-cybersecurity/) by Ali Al Bataineh. Course text CC BY 4.0, code MIT.

[Source repository](https://github.com/aalbata/machine-learning-for-cybersecurity)

[Pinned synthetic dataset](https://raw.githubusercontent.com/aalbata/machine-learning-for-cybersecurity/009634e4f6e414550e79ca704a3164020abd9b03/data/flows.csv)

The model definitions, preprocessing and optional analyses derive from the source lab. This course adaptation adds staged questions, plain-language explanations, daily budget allocation, the family diagnostic and the offline handout.
