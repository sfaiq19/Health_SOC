import json
from hashlib import sha256

import pytest

from hospital_soc.documents import document_path, restore_documents
from hospital_soc.store import seed_lab


def test_document_update_changes_real_file_and_reset_restores_it(lab, headers, login):
    path = document_path(lab.cfg, 'D001')
    original = path.read_bytes()
    response = lab.client.put('/api/documents/D001', headers=headers(login('document-editor')),
                              json={'content': 'Z' * len(original)})
    assert response.status_code == 200
    assert path.read_bytes() != original
    assert response.json['sha256_after'] == sha256(path.read_bytes()).hexdigest()
    manifest = json.loads((lab.cfg.root / 'seed-manifest.json').read_text())
    assert restore_documents(lab.cfg, manifest)['verified'] is True
    assert path.read_bytes() == original


@pytest.mark.parametrize('document_id', ['../outside', '/etc/passwd', 'D999', '..', 'C:\\bad'])
def test_document_ids_never_select_arbitrary_paths(lab, document_id):
    with pytest.raises(ValueError):
        document_path(lab.cfg, document_id)


def test_seed_refuses_existing_unmarked_directory(lab):
    (lab.cfg.root / '.healthcare-soc-runtime').unlink()
    with pytest.raises(ValueError):
        seed_lab(lab.cfg, 1)


def test_reset_refuses_active_run(lab):
    (lab.cfg.root / '.run.lock').write_text('active')
    manifest = json.loads((lab.cfg.root / 'seed-manifest.json').read_text())
    with pytest.raises(ValueError):
        restore_documents(lab.cfg, manifest)


def test_real_hard_link_cannot_mutate_a_file_outside_dummy_root(lab, tmp_path):
    import os
    from hospital_soc.documents import update_document
    outside = tmp_path / 'outside.txt'
    outside.write_bytes(b'original outside data')
    path = lab.cfg.root / 'documents/D001.txt'
    path.unlink()
    os.link(outside, path)
    with pytest.raises(ValueError):
        update_document(lab.cfg, 'D001', b'changed')
    assert outside.read_bytes() == b'original outside data'


def test_restore_prevalidates_hard_links_before_changing_any_document(lab, tmp_path):
    import os
    first = lab.cfg.root / 'documents/D001.txt'
    first.write_bytes(b'keep this until all paths are validated')
    outside = tmp_path / 'outside.txt'
    outside.write_bytes(b'outside')
    last = lab.cfg.root / 'documents/D050.txt'
    last.unlink()
    os.link(outside, last)
    manifest = json.loads((lab.cfg.root / 'seed-manifest.json').read_text())
    with pytest.raises(ValueError):
        restore_documents(lab.cfg, manifest)
    assert first.read_bytes() == b'keep this until all paths are validated'
    assert outside.read_bytes() == b'outside'


def test_real_windows_junction_cannot_redirect_document_updates(lab, tmp_path):
    import os
    import subprocess
    from hospital_soc.documents import update_document
    if os.name != 'nt':
        pytest.skip('Native Windows junction check')
    outside = tmp_path / 'outside-directory'
    outside.mkdir()
    (outside / 'D001.txt').write_bytes(b'outside')
    directory = lab.cfg.root / 'documents'
    backup = lab.cfg.root / 'documents-backup'
    assert directory.resolve().is_relative_to(lab.cfg.root.resolve())
    assert backup.resolve().is_relative_to(lab.cfg.root.resolve())
    directory.rename(backup)
    result = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(directory), str(outside)], capture_output=True)
    if result.returncode:
        backup.rename(directory)
        pytest.fail('Windows junction fixture creation failed')
    try:
        with pytest.raises(ValueError):
            update_document(lab.cfg, 'D001', b'changed')
        assert (outside / 'D001.txt').read_bytes() == b'outside'
    finally:
        assert directory.is_junction() and directory.resolve() == outside.resolve()
        os.rmdir(directory)  # Remove only this verified test junction, never its target recursively.
        backup.rename(directory)
