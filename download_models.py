"""
One-time helper: fetches the two small model files that enable FaceManager's
high-accuracy DNN backend (YuNet detector + SFace recognizer).

Run once, from the project folder:
    python download_models.py

You do NOT need this to run the app - without these two files, FaceManager
automatically uses its built-in LBP fallback, which already fixes the
"shows Unknown" bug, just with a bit less accuracy than the DNN backend.
You also do NOT need dlib or Visual Studio Build Tools for either path.

WHY THIS SCRIPT MIGHT STILL TELL YOU TO DOWNLOAD MANUALLY
-----------------------------------------------------------
Both files are stored on GitHub via Git LFS. A plain HTTP download (which is
all a Python script can do without git/git-lfs installed) fetches a small
LFS *pointer* text file instead of the real model - this is a Git LFS
behavior, not something specific to your machine or network. This script
detects that case and tells you exactly how to get the real file instead.
"""

import os
import urllib.request

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

# Two candidate URLs per file. media.githubusercontent.com is GitHub's Git LFS
# media endpoint and serves the real file over plain HTTP, so it is tried
# first. The raw.githubusercontent.com URL is kept as a fallback in case
# GitHub changes its media endpoint routing.
FILES = {
    "face_detection_yunet_2023mar.onnx": {
        "url": "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
        "fallback_url": "https://raw.githubusercontent.com/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
        "page": "https://github.com/opencv/opencv_zoo/blob/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
        "min_size": 100_000,  # real file is ~232 KB
    },
    "face_recognition_sface_2021dec.onnx": {
        "url": "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
        "fallback_url": "https://raw.githubusercontent.com/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
        "page": "https://github.com/opencv/opencv_zoo/blob/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
        "min_size": 1_000_000,  # real file is ~37 MB
    },
}


def looks_like_lfs_pointer(path, threshold):
    return os.path.getsize(path) < threshold


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    any_missing = False

    for filename, info in FILES.items():
        dest = os.path.join(MODELS_DIR, filename)
        if os.path.exists(dest) and not looks_like_lfs_pointer(dest, info["min_size"]):
            print(f"[skip] {filename} already present ({os.path.getsize(dest):,} bytes)")
            continue

        print(f"[downloading] {filename} ...")
        try:
            urllib.request.urlretrieve(info["url"], dest)
        except Exception as e:
            print(f"  ! primary request failed: {e}")
            try:
                print(f"    trying fallback URL ...")
                urllib.request.urlretrieve(info["fallback_url"], dest)
            except Exception as e2:
                print(f"    ! fallback request failed: {e2}")
                any_missing = True
                continue

        if looks_like_lfs_pointer(dest, info["min_size"]):
            os.remove(dest)
            print(f"  ! got a Git LFS pointer instead of the real file (this is expected -")
            print(f"    GitHub LFS files need a browser or git-lfs, not a plain HTTP request).")
            print(f"    Please download it manually:")
            print(f"      1. Open: {info['page']}")
            print(f"      2. Click the Download button on that page")
            print(f"      3. Save it as: {dest}")
            any_missing = True
        else:
            print(f"  OK ({os.path.getsize(dest):,} bytes) -> {dest}")

    print()
    if any_missing:
        print("Some model files still need a manual download (see instructions above).")
        print("The app runs fine without them - it'll just use the LBP fallback until then.")
    else:
        print("All model files present. FaceManager will use the DNN backend on next run.")


if __name__ == "__main__":
    main()
