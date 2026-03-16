@echo off
git add pyproject.toml pyaegis/rules/__init__.py pyaegis/modules/__init__.py
git commit -m "chore: fix pyproject.toml for PyPI build"
git push
