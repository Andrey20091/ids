import pandas as pd
import pytest

from src.models.train_random_forest import train_random_forest


def test_train_random_forest_requires_min_rows(tmp_path):
    X = pd.DataFrame({"f1": [1.0]})
    y = pd.Series(["BENIGN"])
    with pytest.raises(ValueError, match="at least 2 rows"):
        train_random_forest(X, y, tmp_path)
