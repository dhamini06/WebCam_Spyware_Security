"""
Assets Manager for Webcam Spyware Security
Manages GUI assets, images, and styling
"""

import os
from typing import Optional, Dict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AssetManager:
    """Manages application assets"""
    
    def __init__(self):
        """Initialize asset manager"""
        self.asset_dir = Path(__file__).parent / "assets"
        self.ensure_asset_dirs()
    
    def ensure_asset_dirs(self):
        """Ensure required asset directories exist"""
        dirs = [
            self.asset_dir / "icons",
            self.asset_dir / "images",
            self.asset_dir / "themes",
            self.asset_dir / "fonts",
        ]
        
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def get_asset_path(self, asset_type: str, filename: str) -> Optional[str]:
        """
        Get path to asset file
        
        Args:
            asset_type: Type of asset (icons, images, themes, fonts)
            filename: Asset filename
            
        Returns:
            Full path to asset or None if not found
        """
        path = self.asset_dir / asset_type / filename
        
        if path.exists():
            return str(path)
        
        logger.warning(f"Asset not found: {asset_type}/{filename}")
        return None
    
    def get_icon(self, icon_name: str) -> Optional[str]:
        """Get icon path"""
        return self.get_asset_path("icons", f"{icon_name}.png")
    
    def get_image(self, image_name: str) -> Optional[str]:
        """Get image path"""
        return self.get_asset_path("images", f"{image_name}.png")
    
    def get_theme(self, theme_name: str) -> Optional[str]:
        """Get theme file path"""
        return self.get_asset_path("themes", f"{theme_name}.json")
    
    def get_font(self, font_name: str) -> Optional[str]:
        """Get font file path"""
        return self.get_asset_path("fonts", font_name)


class ThemeManager:
    """Manages application themes"""
    
    # Light theme
    LIGHT_THEME = {
        "bg_primary": "#ffffff",
        "bg_secondary": "#f5f5f5",
        "bg_tertiary": "#e0e0e0",
        "text_primary": "#000000",
        "text_secondary": "#666666",
        "text_tertiary": "#999999",
        "accent": "#1976d2",
        "success": "#388e3c",
        "warning": "#f57c00",
        "danger": "#d32f2f",
    }
    
    # Dark theme
    DARK_THEME = {
        "bg_primary": "#1a1a1a",
        "bg_secondary": "#2a2a2a",
        "bg_tertiary": "#333333",
        "text_primary": "#e0e0e0",
        "text_secondary": "#aaaaaa",
        "text_tertiary": "#777777",
        "accent": "#1f6aa5",
        "success": "#2da346",
        "warning": "#f79646",
        "danger": "#c5504b",
    }
    
    def __init__(self, theme_name: str = "dark"):
        """
        Initialize theme manager
        
        Args:
            theme_name: Theme name (dark, light)
        """
        self.theme_name = theme_name
        self.theme = self._get_theme(theme_name)
    
    @staticmethod
    def _get_theme(theme_name: str) -> Dict[str, str]:
        """Get theme by name"""
        themes = {
            "light": ThemeManager.LIGHT_THEME,
            "dark": ThemeManager.DARK_THEME,
        }
        return themes.get(theme_name, ThemeManager.DARK_THEME)
    
    def get_color(self, color_key: str) -> str:
        """Get theme color"""
        return self.theme.get(color_key, "#000000")
    
    def set_theme(self, theme_name: str):
        """Set active theme"""
        self.theme_name = theme_name
        self.theme = self._get_theme(theme_name)


class StyleManager:
    """Manages widget styles"""
    
    @staticmethod
    def get_button_style(button_type: str = "primary") -> Dict:
        """Get button style"""
        styles = {
            "primary": {
                "fg_color": "#1f6aa5",
                "hover_color": "#155a8c",
                "text_color": "#ffffff",
            },
            "success": {
                "fg_color": "#2da346",
                "hover_color": "#238a39",
                "text_color": "#ffffff",
            },
            "danger": {
                "fg_color": "#c5504b",
                "hover_color": "#9d3f38",
                "text_color": "#ffffff",
            },
            "warning": {
                "fg_color": "#f79646",
                "hover_color": "#d97f2f",
                "text_color": "#ffffff",
            },
            "secondary": {
                "fg_color": "#2a2a2a",
                "hover_color": "#333333",
                "text_color": "#e0e0e0",
            },
        }
        return styles.get(button_type, styles["primary"])
    
    @staticmethod
    def get_entry_style() -> Dict:
        """Get entry field style"""
        return {
            "fg_color": "#2a2a2a",
            "border_color": "#444444",
            "text_color": "#e0e0e0",
            "placeholder_text_color": "#888888",
        }
    
    @staticmethod
    def get_frame_style(frame_type: str = "secondary") -> Dict:
        """Get frame style"""
        styles = {
            "primary": {
                "fg_color": "#1a1a1a",
                "border_color": "#333333",
            },
            "secondary": {
                "fg_color": "#2a2a2a",
                "border_color": "#444444",
            },
            "card": {
                "fg_color": "#252525",
                "border_color": "#3a3a3a",
                "corner_radius": 10,
            },
        }
        return styles.get(frame_type, styles["secondary"])
    
    @staticmethod
    def get_label_style(label_type: str = "primary") -> Dict:
        """Get label style"""
        styles = {
            "primary": {
                "text_color": "#e0e0e0",
                "font": ("Segoe UI", 12),
            },
            "heading": {
                "text_color": "#e0e0e0",
                "font": ("Segoe UI", 18, "bold"),
            },
            "subheading": {
                "text_color": "#aaaaaa",
                "font": ("Segoe UI", 14, "bold"),
            },
            "muted": {
                "text_color": "#888888",
                "font": ("Segoe UI", 10),
            },
            "success": {
                "text_color": "#2da346",
                "font": ("Segoe UI", 12),
            },
            "danger": {
                "text_color": "#c5504b",
                "font": ("Segoe UI", 12),
            },
        }
        return styles.get(label_type, styles["primary"])


class IconManager:
    """Manages icons using emoji"""
    
    ICONS = {
        # Navigation
        "dashboard": "📊",
        "camera": "📹",
        "logs": "📋",
        "users": "👥",
        "policies": "📋",
        "intruders": "🚨",
        "settings": "⚙️",
        "logout": "🚪",
        "user": "👤",
        
        # Status
        "enabled": "✅",
        "disabled": "❌",
        "warning": "⚠️",
        "error": "❌",
        "success": "✔️",
        "info": "ℹ️",
        
        # Actions
        "add": "➕",
        "delete": "🗑️",
        "edit": "✏️",
        "save": "💾",
        "refresh": "🔄",
        "search": "🔍",
        
        # Others
        "lock": "🔒",
        "unlock": "🔓",
        "key": "🔑",
        "alert": "🔔",
        "computer": "💻",
        "network": "🌐",
    }
    
    @staticmethod
    def get_icon(icon_name: str) -> str:
        """Get icon emoji"""
        return IconManager.ICONS.get(icon_name, "•")
    
    @staticmethod
    def get_all_icons() -> Dict[str, str]:
        """Get all icons"""
        return IconManager.ICONS.copy()


# Global instances
_asset_manager: Optional[AssetManager] = None
_theme_manager: Optional[ThemeManager] = None


def get_asset_manager() -> AssetManager:
    """Get global asset manager"""
    global _asset_manager
    if _asset_manager is None:
        _asset_manager = AssetManager()
    return _asset_manager


def get_theme_manager() -> ThemeManager:
    """Get global theme manager"""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test asset manager
    print("=== Asset Manager ===")
    assets = get_asset_manager()
    print(f"Asset directory: {assets.asset_dir}")
    
    # Test theme manager
    print("\n=== Theme Manager ===")
    theme = get_theme_manager()
    print(f"Current theme: {theme.theme_name}")
    print(f"Primary color: {theme.get_color('accent')}")
    
    # Test style manager
    print("\n=== Style Manager ===")
    button_style = StyleManager.get_button_style("primary")
    print(f"Primary button: {button_style}")
    
    # Test icon manager
    print("\n=== Icon Manager ===")
    print(f"Dashboard icon: {IconManager.get_icon('dashboard')}")
    print(f"Settings icon: {IconManager.get_icon('settings')}")
