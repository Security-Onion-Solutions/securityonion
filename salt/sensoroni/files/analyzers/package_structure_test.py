from pathlib import Path


ANALYZERS_DIR = Path(__file__).resolve().parent


class TestAnalyzerPackageStructure:
    def test_each_analyzer_has_package_entrypoint_and_test(self):
        analyzer_dirs = sorted(
            p for p in ANALYZERS_DIR.iterdir() if p.is_dir() and (p / f"{p.name}.py").exists()
        )

        assert analyzer_dirs, "No analyzer directories were discovered"

        missing_files = []
        for analyzer_dir in analyzer_dirs:
            analyzer_name = analyzer_dir.name
            expected = [
                analyzer_dir / "__init__.py",
                analyzer_dir / f"{analyzer_name}.py",
                analyzer_dir / f"{analyzer_name}_test.py",
            ]
            missing = [str(path.relative_to(ANALYZERS_DIR)) for path in expected if not path.exists()]
            if missing:
                missing_files.extend(missing)

        assert not missing_files, "Missing required analyzer files: " + ", ".join(missing_files)
