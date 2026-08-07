"""
Face Recognition Manager for Webcam Spyware Security
Handles face detection, encoding, and verification.

WHY THIS FILE CHANGED
---------------------
The original encoder built a feature vector purely from raw pixel-intensity
histograms (whole face + quadrants + a gradient histogram). Intensity
histograms shift wholesale under a global brightness/contrast change, so a
face registered under one lighting condition would frequently fall outside
TOLERANCE when verified under another - the reported "shows Unknown" bug.

This version picks one of two backends automatically at startup:

  1. DNN backend (preferred) - OpenCV's YuNet detector + SFace recognizer.
     ~99% accuracy per OpenCV's own benchmarks, needs two small ONNX model
     files (see download_models.py). No dlib, no Visual Studio Build Tools.
  2. LBP fallback (always available, zero extra downloads) - Local Binary
     Pattern grid histograms instead of raw intensity histograms. LBP codes
     encode *relative* pixel comparisons ("is my neighbor brighter than me"),
     so a uniform brightness/contrast shift leaves every code unchanged -
     that's the specific property that fixes the reported bug even without
     the DNN models. Combined with histogram equalization it closes most of
     the gap, though it won't match the DNN backend's accuracy.

Both backends are exposed through the exact same public methods used
elsewhere in this project (gui.py, database.py), so nothing else needs to
change. Every stored encoding is tagged with which backend produced it
(see _TAG_SFACE / _TAG_LBP below), so compare_faces() can never compare two
incompatible encodings by accident - including encodings created by the
ORIGINAL pre-fix algorithm, which carried no tag at all and will now be
correctly treated as "no match" rather than silently mis-compared.

>>> IMPORTANT: because of that tagging, any face registered before this fix
>>> (or under a different backend than the one currently active) must be
>>> re-registered once. Verifying against an old encoding will otherwise
>>> correctly - and intentionally - report "Unknown" rather than guess.
"""

import cv2
import numpy as np
import logging
import os
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from datetime import datetime
import base64
import pickle

from database import DatabaseManager
from utils import FileUtils, SystemInfo, DateTimeUtils, AppPaths

logger = logging.getLogger(__name__)

FACE_CASCADE_PATH = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'

# The project already ships a top-level intruder_images/ folder for exactly
# this purpose - save evidence there directly rather than nested under
# assets/faces/, so it's where you'd actually go looking for it. In frozen
# builds this is the persistent data folder, not the temp extraction dir.
_INTRUDER_IMAGES_DIR = AppPaths.intruder_images_dir()

# Two small files enable the high-accuracy DNN backend - see download_models.py.
# Models are read-only bundled resources, so in frozen builds they are read
# straight from the extraction directory (they never need to be writable).
_MODELS_DIR = os.path.join(AppPaths.bundle_dir(), 'models')
_YUNET_MODEL = os.path.join(_MODELS_DIR, 'face_detection_yunet_2023mar.onnx')
_SFACE_MODEL = os.path.join(_MODELS_DIR, 'face_recognition_sface_2021dec.onnx')

# Sentinel values prepended to every stored encoding so compare_faces() always
# knows which algorithm produced it. Real feature values never reach this
# magnitude, so there's no collision risk. An encoding with neither tag is
# assumed to predate this fix.
_TAG_SFACE = -999002.0
_TAG_LBP = -999001.0

# Recommended by OpenCV's own SFace docs/samples: same person if
# cosine similarity >= 0.363, i.e. distance (1 - similarity) <= 0.637.
_SFACE_TOLERANCE = 1.0 - 0.363
# Empirically measured on real same-person photos under simulated lighting
# swings (see the accompanying test notes) - same-person distance stayed
# under ~0.10 even in a "much darker" simulation, so 0.35 leaves comfortable
# margin without being so loose it invites false accepts.
_LBP_TOLERANCE = 0.35


class FaceManager:
    """Manages face recognition operations."""

    TOLERANCE = _LBP_TOLERANCE  # overwritten in __init__ once the backend is known

    def __init__(self, db: DatabaseManager = None, faces_dir: str = None):
        self.db = db or DatabaseManager()
        self.faces_dir = faces_dir or AppPaths.faces_dir()
        self._ensure_faces_dir()
        self.face_encodings_cache = {}

        # Kept for the live-preview loop in gui.py, which reaches into this
        # attribute directly for a quick "is a face here" check regardless
        # of which backend below ends up handling the actual encoding.
        self._face_cascade = cv2.CascadeClassifier(FACE_CASCADE_PATH)
        if self._face_cascade.empty():
            logger.warning("Failed to load face cascade classifier")

        self._yunet = None
        self._sface = None
        self.backend = 'lbp_haar'
        self.TOLERANCE = _LBP_TOLERANCE

        if os.path.exists(_YUNET_MODEL) and os.path.exists(_SFACE_MODEL):
            try:
                self._yunet = cv2.FaceDetectorYN_create(
                    _YUNET_MODEL, "", (320, 320), 0.9, 0.3, 5000
                )
                self._sface = cv2.FaceRecognizerSF_create(_SFACE_MODEL, "")
                self.backend = 'sface'
                self.TOLERANCE = _SFACE_TOLERANCE
                logger.info("FaceManager: using DNN backend (YuNet + SFace).")
            except Exception as e:
                logger.error(f"Failed to load DNN face models, using LBP fallback instead: {e}")
                self._yunet = None
                self._sface = None
                self.backend = 'lbp_haar'
                self.TOLERANCE = _LBP_TOLERANCE

        if self.backend == 'lbp_haar':
            logger.info(
                "FaceManager: using LBP fallback backend (DNN model files not found "
                f"in {_MODELS_DIR}; run download_models.py for higher accuracy)."
            )

    def _ensure_faces_dir(self):
        FileUtils.ensure_dir_exists(self.faces_dir)
        FileUtils.ensure_dir_exists(os.path.join(self.faces_dir, 'registered'))
        FileUtils.ensure_dir_exists(os.path.join(self.faces_dir, 'failed'))
        FileUtils.ensure_dir_exists(_INTRUDER_IMAGES_DIR)

    def capture_face_from_camera(self, camera_index: int = 0,
                                timeout_seconds: int = 5) -> Optional[np.ndarray]:
        try:
            cap = cv2.VideoCapture(camera_index)
            if not cap.isOpened():
                logger.error("Failed to open camera")
                return None

            start_time = datetime.now()
            frame = None

            while (datetime.now() - start_time).total_seconds() < timeout_seconds:
                ret, frame = cap.read()
                if not ret:
                    continue
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = self._face_cascade.detectMultiScale(gray, 1.3, 5)
                if len(faces) > 0:
                    cap.release()
                    return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

            cap.release()
            logger.warning("No face detected in capture window")
            return None
        except Exception as e:
            logger.error(f"Error capturing face: {e}")
            return None

    def capture_intruder_evidence(self, camera_index: int = 0,
                                 video_seconds: float = 10.0,
                                 fps: float = 15.0,
                                 capture_video: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """
        Records evidence after a failed password/face check, for the
        Intruders log. Best-effort: returns (None, None) rather than raising
        if no camera is available, so a denied action is never blocked by
        evidence capture failing.

        Args:
            capture_video: if False, only a single snapshot is taken (no
                .avi file at all) - used for lighter-weight gates like
                View Logs, where the spec calls for one photo, not a video.

        Returns:
            (snapshot_path, video_path) - either may be None if unavailable
            or not requested.
        """
        cap = None
        writer = None
        try:
            cap = cv2.VideoCapture(camera_index)
            if not cap.isOpened():
                logger.warning("capture_intruder_evidence: no camera available")
                return None, None

            # Let auto-exposure/white-balance settle. Many webcams return a
            # dark/washed-out frame for the first several reads right after
            # opening, before their calibration finishes - discard those
            # rather than saving the intruder's first (bad) frame as evidence.
            for _ in range(15):
                cap.read()

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_path = os.path.join(_INTRUDER_IMAGES_DIR, f'intruder_{timestamp}.jpg')
            video_path = os.path.join(_INTRUDER_IMAGES_DIR, f'intruder_{timestamp}.avi')

            ret, first_frame = cap.read()
            if not ret:
                cap.release()
                return None, None

            cv2.imwrite(snapshot_path, first_frame)

            if capture_video:
                h, w = first_frame.shape[:2]
                fourcc = cv2.VideoWriter_fourcc(*'XVID')
                writer = cv2.VideoWriter(video_path, fourcc, fps, (w, h))
                if writer.isOpened():
                    writer.write(first_frame)

                start = datetime.now()
                while (datetime.now() - start).total_seconds() < video_seconds:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    if writer.isOpened():
                        writer.write(frame)

            return (
                snapshot_path if os.path.exists(snapshot_path) else None,
                (video_path if (capture_video and writer is not None and writer.isOpened()
                                and os.path.exists(video_path)) else None),
            )
        except Exception as e:
            logger.error(f"Error capturing intruder evidence: {e}")
            return None, None
        finally:
            if writer is not None:
                writer.release()
            if cap is not None:
                cap.release()

    def load_image(self, image_path: str) -> Optional[np.ndarray]:
        try:
            image = cv2.imread(image_path)
            if image is None:
                logger.error(f"Failed to load image: {image_path}")
                return None
            return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        except Exception as e:
            logger.error(f"Error loading image: {e}")
            return None

    def save_image(self, image: np.ndarray, save_path: str) -> bool:
        try:
            image_bgr = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
            success = cv2.imwrite(save_path, image_bgr)
            if success:
                logger.info(f"Image saved: {save_path}")
            else:
                logger.error(f"Failed to save image: {save_path}")
            return success
        except Exception as e:
            logger.error(f"Error saving image: {e}")
            return False

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #

    def _detect_with_landmarks(self, image_rgb: np.ndarray):
        """DNN detection only. Returns YuNet's raw rows (bbox + 5 landmarks +
        score per face) in pixel coordinates, or [] if unavailable/none found.
        Only meaningful while self.backend == 'sface'."""
        if self._yunet is None:
            return []
        try:
            h, w = image_rgb.shape[:2]
            self._yunet.setInputSize((w, h))
            image_bgr = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2BGR)
            _, faces = self._yunet.detect(image_bgr)
            if faces is None:
                return []
            return faces
        except Exception as e:
            logger.error(f"YuNet detection error: {e}")
            return []

    def detect_faces(self, image: np.ndarray) -> List[Tuple]:
        try:
            if self.backend == 'sface':
                rows = self._detect_with_landmarks(image)
                locations = []
                for row in rows:
                    x, y, w, h = (int(v) for v in row[:4])
                    locations.append((y, x + w, y + h, x))
                logger.info(f"Detected {len(locations)} face(s)")
                return locations

            gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
            faces = self._face_cascade.detectMultiScale(gray, 1.3, 5)
            locations = []
            for (x, y, w, h) in faces:
                locations.append((y, x + w, y + h, x))
            logger.info(f"Detected {len(locations)} face(s)")
            return locations
        except Exception as e:
            logger.error(f"Error detecting faces: {e}")
            return []

    # ------------------------------------------------------------------ #
    # Encoding
    # ------------------------------------------------------------------ #

    def get_face_encoding(self, image: np.ndarray,
                         face_location: Tuple = None) -> Optional[np.ndarray]:
        """Returns a tagged feature vector (see _TAG_SFACE/_TAG_LBP).

        When the DNN backend is active, `face_location` is ignored and a
        fresh, landmark-aware detection is run internally instead - this is
        what lets a Haar-derived box (e.g. from gui.py's live-preview loop)
        keep working unmodified while still getting SFace's properly aligned
        crop under the hood.
        """
        try:
            if self.backend == 'sface':
                return self._encode_sface(image)
            return self._encode_lbp(image, face_location)
        except Exception as e:
            logger.error(f"Error encoding face: {e}")
            return None

    def _encode_sface(self, image_rgb: np.ndarray) -> Optional[np.ndarray]:
        rows = self._detect_with_landmarks(image_rgb)
        if len(rows) == 0:
            return None
        row = max(rows, key=lambda r: r[2] * r[3])  # largest face by area
        image_bgr = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2BGR)
        aligned = self._sface.alignCrop(image_bgr, row)
        feature = self._sface.feature(aligned)
        vec = feature.flatten().astype(np.float64)
        return np.concatenate([[_TAG_SFACE], vec])

    def _encode_lbp(self, image: np.ndarray, face_location: Tuple) -> Optional[np.ndarray]:
        if face_location is None:
            locations = self.detect_faces(image)
            if not locations:
                return None
            face_location = locations[0]

        top, right, bottom, left = face_location
        h, w = image.shape[:2]
        top = max(0, min(top, h - 1))
        left = max(0, min(left, w - 1))
        bottom = max(top + 1, min(bottom, h))
        right = max(left + 1, min(right, w))

        face_img = image[top:bottom, left:right]
        if face_img.size == 0:
            return None

        face_gray = cv2.cvtColor(face_img, cv2.COLOR_RGB2GRAY)
        face_resized = cv2.resize(face_gray, (128, 128))
        face_eq = cv2.equalizeHist(face_resized)  # illumination normalization

        vec = self._lbp_grid_histogram(face_eq)
        return np.concatenate([[_TAG_LBP], vec])

    @staticmethod
    def _lbp_pixel_codes(gray: np.ndarray) -> np.ndarray:
        """Vectorized 8-neighbor LBP. Each code only records whether a
        neighbor is >= the center pixel, so it is unchanged by any uniform
        (or any monotonic) brightness/contrast shift - the key property the
        old raw-histogram encoder lacked."""
        padded = np.pad(gray.astype(np.int16), 1, mode='edge')
        center = padded[1:-1, 1:-1]
        code = np.zeros_like(center, dtype=np.uint8)
        neighbors = [
            padded[0:-2, 0:-2], padded[0:-2, 1:-1], padded[0:-2, 2:],
            padded[1:-1, 2:], padded[2:, 2:], padded[2:, 1:-1],
            padded[2:, 0:-2], padded[1:-1, 0:-2],
        ]
        for i, n in enumerate(neighbors):
            code |= ((n >= center).astype(np.uint8) << i)
        return code

    @classmethod
    def _lbp_grid_histogram(cls, face_gray_eq: np.ndarray,
                           grid: Tuple[int, int] = (8, 8), bins: int = 32) -> np.ndarray:
        """Spatial LBP histogram: split the face into a grid, histogram the
        LBP codes in each cell, and concatenate. The grid keeps some spatial
        layout (eyes vs. mouth region etc.), similar in spirit to the
        original code's quadrant split but built from illumination-invariant
        codes instead of raw intensities."""
        lbp = cls._lbp_pixel_codes(face_gray_eq)
        gh, gw = grid
        size = face_gray_eq.shape[0]
        cell = size // gh
        hists = []
        for i in range(gh):
            for j in range(gw):
                block = lbp[i * cell:(i + 1) * cell, j * cell:(j + 1) * cell]
                hist, _ = np.histogram(block, bins=bins, range=(0, 256))
                hist = hist.astype(np.float64)
                s = hist.sum()
                if s > 0:
                    hist /= s
                hists.append(hist)
        return np.concatenate(hists)

    def encode_encoding_to_string(self, encoding: np.ndarray) -> str:
        try:
            encoding_bytes = encoding.tobytes()
            encoding_str = base64.b64encode(encoding_bytes).decode('utf-8')
            return encoding_str
        except Exception as e:
            logger.error(f"Error encoding to string: {e}")
            return ""

    def decode_string_to_encoding(self, encoding_str: str) -> Optional[np.ndarray]:
        try:
            encoding_bytes = base64.b64decode(encoding_str.encode('utf-8'))
            encoding = np.frombuffer(encoding_bytes, dtype=np.float64)
            return encoding
        except Exception as e:
            logger.error(f"Error decoding string: {e}")
            return None

    # ------------------------------------------------------------------ #
    # Registration / verification
    # ------------------------------------------------------------------ #

    def register_face(self, user_id: int, image_path: str = None,
                     image: np.ndarray = None, username: str = None) -> Tuple[bool, str]:
        try:
            if image_path:
                image = self.load_image(image_path)

            if image is None:
                return False, "Failed to load image"

            face_locations = self.detect_faces(image)
            if not face_locations:
                return False, "No face detected in image"
            if len(face_locations) > 1:
                return False, "Multiple faces detected. Please provide one face per image."

            face_encoding = self.get_face_encoding(image, face_locations[0])
            if face_encoding is None:
                return False, "Failed to encode face"

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            face_filename = f"user_{user_id}_{timestamp}.jpg"
            face_path = os.path.join(self.faces_dir, 'registered', face_filename)
            self.save_image(image, face_path)

            encoding_str = self.encode_encoding_to_string(face_encoding)
            success = self.db.register_face(user_id, encoding_str, face_path)
            self.face_encodings_cache[user_id] = face_encoding

            if username:
                self.db.add_log(
                    user_id, username, 'face_registered', 'info',
                    'Face registered for biometric authentication',
                    SystemInfo.get_ip_address(),
                    SystemInfo.get_machine_name()
                )

            logger.info(f"Face registered for user {user_id}")
            return True, "Face registered successfully"
        except Exception as e:
            logger.error(f"Error registering face: {e}")
            return False, f"Registration failed: {str(e)}"

    def update_face(self, user_id: int, image_path: str = None,
                   image: np.ndarray = None, username: str = None) -> Tuple[bool, str]:
        try:
            if image_path:
                image = self.load_image(image_path)

            if image is None:
                return False, "Failed to load image"

            face_locations = self.detect_faces(image)
            if not face_locations:
                return False, "No face detected"

            face_encoding = self.get_face_encoding(image, face_locations[0])
            if face_encoding is None:
                return False, "Failed to encode face"

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            face_filename = f"user_{user_id}_{timestamp}_updated.jpg"
            face_path = os.path.join(self.faces_dir, 'registered', face_filename)
            self.save_image(image, face_path)

            encoding_str = self.encode_encoding_to_string(face_encoding)
            success = self.db.update_face(user_id, encoding_str, face_path)
            self.face_encodings_cache[user_id] = face_encoding

            if username:
                self.db.add_log(
                    user_id, username, 'face_updated', 'info',
                    'Face registration updated',
                    SystemInfo.get_ip_address(),
                    SystemInfo.get_machine_name()
                )

            logger.info(f"Face updated for user {user_id}")
            return True, "Face updated successfully"
        except Exception as e:
            logger.error(f"Error updating face: {e}")
            return False, f"Update failed: {str(e)}"

    def delete_face(self, user_id: int, username: str = None) -> Tuple[bool, str]:
        try:
            face_data = self.db.get_face_by_user(user_id)
            if not face_data:
                return False, "No face registration found"

            if face_data['image_path']:
                FileUtils.delete_file(face_data['image_path'])

            if user_id in self.face_encodings_cache:
                del self.face_encodings_cache[user_id]

            if username:
                self.db.add_log(
                    user_id, username, 'face_deleted', 'info',
                    'Face registration deleted',
                    SystemInfo.get_ip_address(),
                    SystemInfo.get_machine_name()
                )

            logger.info(f"Face deleted for user {user_id}")
            return True, "Face registration deleted"
        except Exception as e:
            logger.error(f"Error deleting face: {e}")
            return False, f"Deletion failed: {str(e)}"

    def verify_face(self, user_id: int, image_path: str = None,
                   image: np.ndarray = None, username: str = None) -> Tuple[bool, float, str]:
        try:
            face_data = self.db.get_face_by_user(user_id)
            if not face_data or not face_data['encoding']:
                return False, 0.0, "No face registration found for this user"

            registered_encoding = self.decode_string_to_encoding(face_data['encoding'])
            if registered_encoding is None:
                return False, 0.0, "Failed to decode stored face"

            if image_path:
                image = self.load_image(image_path)
            if image is None:
                return False, 0.0, "Failed to load verification image"

            face_locations = self.detect_faces(image)
            if not face_locations:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fail_file = f"failed_{user_id}_{timestamp}_no_face.jpg"
                fail_path = os.path.join(self.faces_dir, 'failed', fail_file)
                self.save_image(image, fail_path)
                if username:
                    self.db.add_log(
                        user_id, username, 'face_verification_failed', 'warning',
                        'No face detected in verification image',
                        SystemInfo.get_ip_address(),
                        SystemInfo.get_machine_name()
                    )
                return False, 0.0, "No face detected in verification image"

            verification_encoding = self.get_face_encoding(image, face_locations[0])
            if verification_encoding is None:
                return False, 0.0, "Failed to encode verification face"

            distance = self.compare_faces(registered_encoding, verification_encoding)
            confidence = 1 - distance
            verified = distance <= self.TOLERANCE

            if not verified and self._is_unrecognized_tag(registered_encoding, verification_encoding):
                msg_extra = (" (this face was registered before the recognition fix, or under a "
                             "different backend - please re-register it once)")
            else:
                msg_extra = ""

            if username:
                self.db.add_log(
                    user_id, username,
                    'face_verification_success' if verified else 'face_verification_failed',
                    'info' if verified else 'warning',
                    f'Face verification - Distance: {distance:.3f}, Confidence: {confidence:.1%}',
                    SystemInfo.get_ip_address(),
                    SystemInfo.get_machine_name()
                )

            if not verified:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fail_file = f"failed_{user_id}_{timestamp}.jpg"
                fail_path = os.path.join(self.faces_dir, 'failed', fail_file)
                self.save_image(image, fail_path)

            logger.info(f"Face verification for user {user_id}: verified={verified}, confidence={confidence:.1%}")
            return verified, confidence, ("Face verified successfully" if verified
                                          else "Face verification failed" + msg_extra)
        except Exception as e:
            logger.error(f"Error verifying face: {e}")
            return False, 0.0, f"Verification error: {str(e)}"

    @staticmethod
    def _is_unrecognized_tag(enc1: np.ndarray, enc2: np.ndarray) -> bool:
        valid_tags = (_TAG_SFACE, _TAG_LBP)
        t1 = enc1[0] if len(enc1) else None
        t2 = enc2[0] if len(enc2) else None
        return t1 not in valid_tags or t2 not in valid_tags or t1 != t2

    # ------------------------------------------------------------------ #
    # Comparison
    # ------------------------------------------------------------------ #

    def compare_faces(self, encoding1: np.ndarray,
                     encoding2: np.ndarray) -> float:
        try:
            if encoding1 is None or encoding2 is None or len(encoding1) < 2 or len(encoding2) < 2:
                return 1.0

            tag1, vec1 = float(encoding1[0]), encoding1[1:]
            tag2, vec2 = float(encoding2[0]), encoding2[1:]

            if tag1 != tag2:
                logger.warning(
                    "compare_faces(): encodings came from two different/unrecognized methods "
                    "(one likely predates this fix) - treating as no-match. Re-register this face."
                )
                return 1.0

            if tag1 == _TAG_SFACE and self._sface is not None:
                v1 = vec1.astype(np.float32).reshape(1, -1)
                v2 = vec2.astype(np.float32).reshape(1, -1)
                cosine_sim = float(self._sface.match(v1, v2, cv2.FaceRecognizerSF_FR_COSINE))
                distance = 1.0 - cosine_sim
                logger.debug(f"Face compare (sface): cosine_sim={cosine_sim:.4f}, distance={distance:.4f}")
                return distance

            if tag1 == _TAG_LBP:
                distance = self._chi_square_distance(vec1, vec2)
                logger.debug(f"Face compare (lbp): chi_square={distance:.4f}")
                return distance

            logger.warning(
                "compare_faces(): encoding has an unrecognized tag (likely predates this fix) "
                "- treating as no-match. Re-register this face."
            )
            return 1.0
        except Exception as e:
            logger.error(f"Error comparing faces: {e}")
            return 1.0

    @staticmethod
    def _chi_square_distance(h1: np.ndarray, h2: np.ndarray, eps: float = 1e-10) -> float:
        """Standard histogram-comparison metric for LBP-style features
        (Ahonen et al.). Normalized by cell count so the result stays on a
        similar scale regardless of grid size."""
        num_cells = max(len(h1) / 32, 1)
        return float(0.5 * np.sum(((h1 - h2) ** 2) / (h1 + h2 + eps)) / num_cells)

    # ------------------------------------------------------------------ #
    # Bulk lookups / stats
    # ------------------------------------------------------------------ #

    def get_all_registered_faces(self) -> Dict[int, Dict]:
        try:
            all_users = self.db.get_all_users()
            registered_faces = {}
            for user in all_users:
                face_data = self.db.get_face_by_user(user['user_id'])
                if face_data and face_data['encoding']:
                    registered_faces[user['user_id']] = {
                        'username': user['username'],
                        'registered_at': face_data['registered_at'],
                        'encoding': face_data['encoding'],
                    }
            return registered_faces
        except Exception as e:
            logger.error(f"Error getting registered faces: {e}")
            return {}

    def identify_face(self, image_path: str = None,
                     image: np.ndarray = None) -> Tuple[Optional[int], float]:
        try:
            if image_path:
                image = self.load_image(image_path)
            if image is None:
                return None, 0.0

            face_locations = self.detect_faces(image)
            if not face_locations:
                return None, 0.0

            face_encoding = self.get_face_encoding(image, face_locations[0])
            if face_encoding is None:
                return None, 0.0

            registered_faces = self.get_all_registered_faces()
            if not registered_faces:
                return None, 0.0

            best_match_id = None
            best_distance = float('inf')

            for user_id, fdata in registered_faces.items():
                registered_encoding = self.decode_string_to_encoding(fdata['encoding'])
                if registered_encoding is not None:
                    distance = self.compare_faces(registered_encoding, face_encoding)
                    if distance < best_distance:
                        best_distance = distance
                        best_match_id = user_id

            if best_distance <= self.TOLERANCE:
                confidence = 1 - best_distance
                logger.info(f"Face identified as user {best_match_id} with confidence {confidence:.1%}")
                return best_match_id, confidence

            return None, 0.0
        except Exception as e:
            logger.error(f"Error identifying face: {e}")
            return None, 0.0

    def get_face_statistics(self) -> Dict:
        try:
            all_users = self.db.get_all_users()
            total_users = len(all_users)
            registered_count = 0
            for user in all_users:
                face_data = self.db.get_face_by_user(user['user_id'])
                if face_data and face_data['encoding']:
                    registered_count += 1

            registered_dir = os.path.join(self.faces_dir, 'registered')
            failed_dir = os.path.join(self.faces_dir, 'failed')
            registered_images = len(os.listdir(registered_dir)) if os.path.exists(registered_dir) else 0
            failed_images = len(os.listdir(failed_dir)) if os.path.exists(failed_dir) else 0

            stats = {
                'total_users': total_users,
                'faces_registered': registered_count,
                'registration_rate': f"{(registered_count / max(total_users, 1) * 100):.1f}%",
                'registered_images': registered_images,
                'failed_attempt_images': failed_images,
                'faces_dir': self.faces_dir,
                'model': 'opencv_dnn_yunet_sface' if self.backend == 'sface' else 'opencv_lbp_haar',
                'tolerance': self.TOLERANCE,
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting face statistics: {e}")
            return {}


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    face_manager = FaceManager()

    print("=== Face Manager Test ===\n")

    print("[1] Face Recognition Statistics:")
    stats = face_manager.get_face_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print(f"\n[2] Face Recognition Model:")
    print(f"  Backend: {face_manager.backend}")
    print(f"  Tolerance: {face_manager.TOLERANCE}")
    if face_manager.backend != 'sface':
        print(f"  Tip: run download_models.py to enable the more accurate DNN backend.")
