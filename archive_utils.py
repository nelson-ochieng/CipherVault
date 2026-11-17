"""Create ZIP archives of directories; decrypted archives are not auto-extracted."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

def archive_folder(folder, destination, progress=None):
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError('Folder not found')
    dest = Path(destination).resolve()
    if dest.exists():
        raise FileExistsError('Archive already exists')
    if dest.is_relative_to(root):
        raise ValueError('Archive destination must be outside the selected folder')
    files = [p for p in root.rglob('*') if p.is_file() and not p.is_symlink()]
    with ZipFile(dest, 'x', compression=ZIP_DEFLATED, allowZip64=True) as z:
        for index, path in enumerate(files, 1):
            z.write(path, arcname=str(Path(root.name) / path.relative_to(root)))
            if progress: progress(index, len(files))
