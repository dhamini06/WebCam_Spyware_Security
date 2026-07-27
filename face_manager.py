"""
Face Recognition Manager for Webcam Spyware Security
Handles face detection, encoding, and verification using OpenCV only
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
from utils import FileUtils, SystemInfo, DateTimeUtils

logger = logging.getLogger(__name__)

FACE_CASCADE_PATH = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'


class FaceManager:
    """Manages face recognition operations using OpenCV"""

    TOLERANCE = 0.65

    def __init__(self, db: DatabaseManager = None, faces_dir: str = None):
        self.db = db or DatabaseManager()
        self.faces_dir = faces_dir or os.path.join(
            os.path.dirname(__file__), 'assets', 'faces'
        )
        self._ensure_faces_dir()
        self.face_encodings_cache = {}
        self._face_cascade = cv2.CascadeClassifier(FACE_CASCADE_PATH)
        if self._face_cascade.empty():
            logger.warning("Failed to load face cascade classifier")

    def _ensure_faces_dir(self):
        FileUtils.ensure_dir_exists(self.faces_dir)
        FileUtils.ensure_dir_exists(os.path.join(self.faces_dir, 'registered'))
        FileUtils.ensure_dir_exists(os.path.join(self.faces_dir, 'failed'))

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

    def detect_faces(self, image: np.ndarray) -> List[Tuple]:
        try:
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

    def get_face_encoding(self, image: np.ndarray,
                         face_location: Tuple = None) -> Optional[np.ndarray]:
        try:
            if face_location is None:
                face_locations = self.detect_faces(image)
                if not face_locations:
                    return None
                face_location = face_locations[0]

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

            # Full face histogram
            hist_full = cv2.calcHist([face_resized], [0], None, [64], [0, 256])
            cv2.normalize(hist_full, hist_full, 0, 1, cv2.NORM_MINMAX)

            # Top half histogram (forehead/eyes region)
            top_half = face_resized[:64, :]
            hist_top = cv2.calcHist([top_half], [0], None, [32], [0, 256])
            cv2.normalize(hist_top, hist_top, 0, 1, cv2.NORM_MINMAX)

            # Bottom half histogram (mouth/chin region)
            bot_half = face_resized[64:, :]
            hist_bot = cv2.calcHist([bot_half], [0], None, [32], [0, 256])
            cv2.normalize(hist_bot, hist_bot, 0, 1, cv2.NORM_MINMAX)

            # Left half
            left_half = face_resized[:, :64]
            hist_left = cv2.calcHist([left_half], [0], None, [32], [0, 256])
            cv2.normalize(hist_left, hist_left, 0, 1, cv2.NORM_MINMAX)

            # Right half
            right_half = face_resized[:, 64:]
            hist_right = cv2.calcHist([right_half], [0], None, [32], [0, 256])
            cv2.normalize(hist_right, hist_right, 0, 1, cv2.NORM_MINMAX)

            # Gradient magnitude for texture
            gx = cv2.Sobel(face_resized, cv2.CV_64F, 1, 0, ksize=3)
            gy = cv2.Sobel(face_resized, cv2.CV_64F, 0, 1, ksize=3)
            grad_mag = np.sqrt(gx**2 + gy**2)
            grad_mag = np.uint8(np.clip(grad_mag, 0, 255))
            hist_grad = cv2.calcHist([grad_mag], [0], None, [32], [0, 256])
            cv2.normalize(hist_grad, hist_grad, 0, 1, cv2.NORM_MINMAX)

            # Combine all features
            encoding = np.concatenate([
                hist_full.flatten(),    # 64 values
                hist_top.flatten(),     # 32 values
                hist_bot.flatten(),     # 32 values
                hist_left.flatten(),    # 32 values
                hist_right.flatten(),   # 32 values
                hist_grad.flatten(),    # 32 values
            ])

            return encoding
        except Exception as e:
            logger.error(f"Error encoding face: {e}")
            return None

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
            return verified, confidence, "Face verified successfully" if verified else "Face verification failed"
        except Exception as e:
            logger.error(f"Error verifying face: {e}")
            return False, 0.0, f"Verification error: {str(e)}"

    def compare_faces(self, encoding1: np.ndarray,
                     encoding2: np.ndarray) -> float:
        try:
            if encoding1.shape != encoding2.shape:
                min_len = min(len(encoding1), len(encoding2))
                encoding1 = encoding1[:min_len]
                encoding2 = encoding2[:min_len]

            # Normalized correlation distance (0 = identical, 1 = completely different)
            e1 = encoding1.astype(np.float64).flatten()
            e2 = encoding2.astype(np.float64).flatten()

            # L2 normalize
            n1 = np.linalg.norm(e1)
            n2 = np.linalg.norm(e2)
            if n1 < 1e-10 or n2 < 1e-10:
                return 1.0

            e1 = e1 / n1
            e2 = e2 / n2

            # Cosine distance
            cosine_sim = np.dot(e1, e2)
            cosine_dist = 1.0 - float(np.clip(cosine_sim, -1.0, 1.0))

            # Histogram intersection distance (1 - intersection)
            h1 = encoding1 / (np.sum(encoding1) + 1e-10)
            h2 = encoding2 / (np.sum(encoding2) + 1e-10)
            intersection = np.minimum(h1, h2).sum()
            hist_dist = 1.0 - intersection

            # Combined
            combined = 0.6 * cosine_dist + 0.4 * hist_dist
            logger.debug(f"Face compare: cosine={cosine_dist:.4f}, hist={hist_dist:.4f}, combined={combined:.4f}")
            return float(combined)
        except Exception as e:
            logger.error(f"Error comparing faces: {e}")
            return 1.0

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
                'model': 'opencv_haar',
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
    print(f"  Model: OpenCV Haar Cascade")
    print(f"  Tolerance: {FaceManager.TOLERANCE}")
