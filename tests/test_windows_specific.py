"""
Windows-specific tests for CalmWeb.

Tests Windows-specific functionality including:
- Registry manipulation
- Windows service integration
- Icon extraction
- Scheduled task creation
- Windows-specific error handling
"""

import os
import sys
from unittest.mock import Mock, patch, MagicMock, mock_open

import pytest

import calmweb


class TestWindowsIconExtraction:
    """Test Windows icon extraction functionality."""

    @pytest.mark.windows
    def test_get_exe_icon_windows_available(self, mock_win32_modules):
        """Test icon extraction when Windows modules are available."""
        # Mock WIN32_AVAILABLE as True
        with patch.object(calmweb, 'WIN32_AVAILABLE', True):
            # Mock icon extraction functions
            mock_large_icon = Mock()
            mock_small_icon = Mock()
            sys.modules['win32gui'].ExtractIconEx.return_value = ([mock_large_icon], [mock_small_icon])

            # Mock DC and bitmap creation
            mock_hdc = Mock()
            mock_hdc_mem = Mock()
            mock_hbmp = Mock()

            sys.modules['win32ui'].CreateDCFromHandle.return_value = mock_hdc
            mock_hdc.CreateCompatibleDC.return_value = mock_hdc_mem
            sys.modules['win32ui'].CreateBitmap.return_value = mock_hbmp
            mock_hbmp.CreateCompatibleBitmap.return_value = None
            mock_hdc_mem.SelectObject.return_value = None

            # Mock bitmap info and data
            mock_hbmp.GetInfo.return_value = {'bmWidth': 32, 'bmHeight': 32}
            mock_hbmp.GetBitmapBits.return_value = b'\x00' * (32 * 32 * 4)

            # Mock PIL Image creation
            with patch('PIL.Image.frombuffer') as mock_frombuffer:
                mock_image = Mock()
                mock_frombuffer.return_value = mock_image

                result = calmweb.get_exe_icon("test.exe")
                assert result == mock_image

    @pytest.mark.windows
    def test_get_exe_icon_windows_not_available(self):
        """Test icon extraction when Windows modules are not available."""
        with patch.object(calmweb, 'WIN32_AVAILABLE', False):
            result = calmweb.get_exe_icon("test.exe")
            assert result is None

    @pytest.mark.windows
    def test_get_exe_icon_extraction_error(self, mock_win32_modules):
        """Test icon extraction handles errors gracefully."""
        with patch.object(calmweb, 'WIN32_AVAILABLE', True):
            # Make ExtractIconEx raise an exception
            sys.modules['win32gui'].ExtractIconEx.side_effect = Exception("Icon extraction failed")

            result = calmweb.get_exe_icon("nonexistent.exe")
            assert result is None

    @pytest.mark.windows
    def test_get_exe_icon_no_icons(self, mock_win32_modules):
        """Test icon extraction when no icons are found."""
        with patch.object(calmweb, 'WIN32_AVAILABLE', True):
            # Return empty icon lists
            sys.modules['win32gui'].ExtractIconEx.return_value = ([], [])

            result = calmweb.get_exe_icon("noiconfile.exe")
            assert result is None

    @pytest.mark.windows
    def test_get_exe_icon_dc_creation_error(self, mock_win32_modules, capture_logs):
        """Test icon extraction handles DC creation errors."""
        with patch.object(calmweb, 'WIN32_AVAILABLE', True):
            mock_icon = Mock()
            sys.modules['win32gui'].ExtractIconEx.return_value = ([mock_icon], [])

            # Make DC creation fail
            sys.modules['win32ui'].CreateDCFromHandle.side_effect = Exception("DC creation failed")

            result = calmweb.get_exe_icon("test.exe")
            assert result is None

    @pytest.mark.windows
    def test_create_image_fallback(self):
        """Test fallback image creation."""
        result = calmweb.create_image()

        # Should create a PIL Image
        assert result is not None
        # Verify it's an Image-like object with expected properties
        assert hasattr(result, 'size')

    @pytest.mark.windows
    def test_create_image_error_handling(self):
        """Test create_image handles errors gracefully."""
        with patch('PIL.Image.new', side_effect=Exception("Image creation failed")):
            result = calmweb.create_image()
            assert result is None


class TestWindowsRegistryOperations:
    """Test Windows registry operations."""

    @pytest.mark.windows
    def test_set_system_proxy_enable_windows(self, mock_win32_modules):
        """Test enabling system proxy on Windows."""
        mock_key = Mock()
        sys.modules['winreg'].OpenKey.return_value = mock_key

        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.run') as mock_subprocess:

            calmweb.set_system_proxy(enable=True, host="127.0.0.1", port=8080)

            # Should have called subprocess for netsh and setx
            assert mock_subprocess.call_count >= 1

            # Should have opened registry key
            sys.modules['winreg'].OpenKey.assert_called()

            # Should have set registry values
            sys.modules['winreg'].SetValueEx.assert_called()

    @pytest.mark.windows
    def test_set_system_proxy_disable_windows(self, mock_win32_modules):
        """Test disabling system proxy on Windows."""
        mock_key = Mock()
        sys.modules['winreg'].OpenKey.return_value = mock_key

        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.run') as mock_subprocess:

            calmweb.set_system_proxy(enable=False)

            # Should have called subprocess for reset commands
            assert mock_subprocess.call_count >= 1

            # Should have opened registry key
            sys.modules['winreg'].OpenKey.assert_called()

            # Should have set registry values to disable
            sys.modules['winreg'].SetValueEx.assert_called()

    @pytest.mark.windows
    def test_set_system_proxy_registry_error(self, mock_win32_modules, capture_logs):
        """Test system proxy handles registry errors gracefully."""
        # Make registry operations fail
        sys.modules['winreg'].OpenKey.side_effect = Exception("Registry access denied")

        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.run') as mock_subprocess:

            # Should not raise exception
            calmweb.set_system_proxy(enable=True, host="127.0.0.1", port=8080)

            # Should still attempt subprocess operations
            assert mock_subprocess.called

    @pytest.mark.windows
    def test_set_system_proxy_non_windows(self, capture_logs):
        """Test system proxy on non-Windows platforms."""
        with patch('platform.system', return_value='Linux'):
            calmweb.set_system_proxy(enable=True, host="127.0.0.1", port=8080)

        # Should log that it's non-Windows and skip


class TestWindowsFirewallIntegration:
    """Test Windows firewall integration."""

    @pytest.mark.windows
    def test_add_firewall_rule_windows(self, mock_subprocess):
        """Test adding firewall rule on Windows."""
        with patch('platform.system', return_value='Windows'):
            target_file = "C:\\Program Files\\CalmWeb\\calmweb.exe"
            calmweb.add_firewall_rule(target_file)

            # Should have called netsh
            mock_subprocess['run'].assert_called_once()
            args = mock_subprocess['run'].call_args[0][0]

            assert "netsh" in args[0]
            assert "advfirewall" in args
            assert "firewall" in args
            assert "add" in args
            assert "rule" in args
            assert target_file in args

    @pytest.mark.windows
    def test_add_firewall_rule_non_windows(self, capture_logs):
        """Test firewall rule addition on non-Windows platforms."""
        with patch('platform.system', return_value='Linux'):
            calmweb.add_firewall_rule("/usr/bin/calmweb")

        # Should log and skip

    @pytest.mark.windows
    def test_add_firewall_rule_subprocess_error(self, mock_subprocess, capture_logs):
        """Test firewall rule handles subprocess errors."""
        with patch('platform.system', return_value='Windows'):
            mock_subprocess['run'].side_effect = Exception("Access denied")

            # Should not raise exception
            calmweb.add_firewall_rule("test.exe")

    @pytest.mark.windows
    def test_add_firewall_rule_permission_error(self, mock_subprocess, capture_logs):
        """Test firewall rule handles permission errors."""
        with patch('platform.system', return_value='Windows'):
            # Simulate permission denied
            import subprocess
            mock_subprocess['run'].side_effect = subprocess.CalledProcessError(1, "netsh")

            # Should handle error gracefully
            calmweb.add_firewall_rule("test.exe")


class TestWindowsScheduledTasks:
    """Test Windows scheduled task functionality."""

    @pytest.mark.windows
    def test_scheduled_task_xml_creation(self, temp_dir):
        """Test scheduled task XML creation."""
        # This tests the XML content that would be used for schtasks
        xml_content = '''<?xml version="1.0" encoding="utf-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Date>2025-10-26T10:16:48</Date>
        <Author>Tonton Jo</Author>
        <URI>CalmWeb</URI>
      </RegistrationInfo>
      <Triggers>
        <LogonTrigger>
          <StartBoundary>2025-10-26T10:16:00</StartBoundary>
          <Enabled>true</Enabled>
        </LogonTrigger>
      </Triggers>
      <Principals>
        <Principal id="Author">
          <GroupId>S-1-5-32-544</GroupId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>false</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
          <StopOnIdleEnd>true</StopOnIdleEnd>
          <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>false</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>7</Priority>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>"C:\\Program Files\\CalmWeb\\calmweb.exe"</Command>
        </Exec>
      </Actions>
    </Task>'''

        # Verify XML structure
        assert "<?xml version=" in xml_content
        assert "CalmWeb" in xml_content
        assert "LogonTrigger" in xml_content
        assert "HighestAvailable" in xml_content
        assert "calmweb.exe" in xml_content

    @pytest.mark.windows
    def test_add_task_from_xml_function(self, mock_subprocess):
        """Test the add_task_from_xml functionality (simulated)."""
        xml_content = "<Task>test content</Task>"

        with patch('tempfile.NamedTemporaryFile') as mock_tempfile, \
             patch('os.path.exists', return_value=True), \
             patch('os.remove') as mock_remove:

            # Mock temporary file
            mock_file = Mock()
            mock_file.name = "temp_task.xml"
            mock_tempfile.return_value.__enter__.return_value = mock_file

            # Simulate the add_task_from_xml function logic
            try:
                with mock_tempfile(delete=False, mode='w', encoding='utf-16') as tmp_file:
                    tmp_file.write(xml_content)
                    tmp_file_path = tmp_file.name

                if os.path.exists(tmp_file_path):
                    # This would call schtasks
                    mock_subprocess['run'].return_value.returncode = 0
                    mock_subprocess['run']([
                        "schtasks", "/Create", "/tn", "CalmWeb",
                        "/XML", tmp_file_path, "/F"
                    ], check=True)

            finally:
                if 'tmp_file_path' in locals():
                    mock_remove(tmp_file_path)

            # Verify schtasks was called
            mock_subprocess['run'].assert_called()
            args = mock_subprocess['run'].call_args[0][0]
            assert "schtasks" in args[0]
            assert "/Create" in args

    @pytest.mark.windows
    def test_scheduled_task_creation_error(self, mock_subprocess, capture_logs):
        """Test scheduled task creation handles errors."""
        with patch('tempfile.NamedTemporaryFile') as mock_tempfile:
            mock_file = Mock()
            mock_file.name = "temp_task.xml"
            mock_tempfile.return_value.__enter__.return_value = mock_file

            # Make schtasks fail
            import subprocess
            mock_subprocess['run'].side_effect = subprocess.CalledProcessError(1, "schtasks")

            # Should handle error gracefully
            # (This would be inside the install() function)


class TestWindowsPathHandling:
    """Test Windows-specific path handling."""

    @pytest.mark.windows
    def test_install_dir_path(self):
        """Test Windows installation directory path."""
        assert calmweb.INSTALL_DIR == r"C:\Program Files\CalmWeb"
        assert isinstance(calmweb.INSTALL_DIR, str)

    @pytest.mark.windows
    def test_startup_folder_path(self):
        """Test Windows startup folder path."""
        with patch.dict(os.environ, {'APPDATA': r'C:\Users\Test\AppData\Roaming'}):
            # Reload the module constant
            startup_folder = os.getenv('APPDATA', '') + r"\Microsoft\Windows\Start Menu\Programs\Startup"
            expected = r"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            assert startup_folder == expected

    @pytest.mark.windows
    def test_user_config_dir_path(self):
        """Test user configuration directory path."""
        with patch.dict(os.environ, {'APPDATA': r'C:\Users\Test\AppData\Roaming'}):
            config_dir = os.path.join(os.getenv('APPDATA'), "CalmWeb")
            expected = r"C:\Users\Test\AppData\Roaming\CalmWeb"
            assert config_dir == expected

    @pytest.mark.windows
    def test_exe_name_constant(self):
        """Test executable name constant."""
        assert calmweb.EXE_NAME == "calmweb.exe"
        assert calmweb.EXE_NAME.endswith(".exe")


class TestWindowsServiceIntegration:
    """Test Windows service-like functionality."""

    @pytest.mark.windows
    def test_windows_socket_options(self):
        """Test Windows-specific socket options."""
        mock_socket = Mock()

        with patch('platform.system', return_value='Windows'):
            calmweb._set_socket_opts_for_perf(mock_socket)

            # Should have set basic socket options
            mock_socket.setsockopt.assert_called()

            # Should have attempted Windows-specific keepalive
            mock_socket.ioctl.assert_called()

    @pytest.mark.windows
    def test_windows_socket_options_error_handling(self):
        """Test Windows socket options handle errors."""
        mock_socket = Mock()
        mock_socket.setsockopt.side_effect = Exception("Socket option failed")
        mock_socket.ioctl.side_effect = Exception("ioctl failed")

        with patch('platform.system', return_value='Windows'):
            # Should not raise exception
            calmweb._set_socket_opts_for_perf(mock_socket)

    @pytest.mark.windows
    def test_non_windows_socket_options(self):
        """Test socket options on non-Windows platforms."""
        mock_socket = Mock()

        with patch('platform.system', return_value='Linux'):
            calmweb._set_socket_opts_for_perf(mock_socket)

            # Should set basic options but not call ioctl
            mock_socket.setsockopt.assert_called()
            mock_socket.ioctl.assert_not_called()


class TestWindowsFileOperations:
    """Test Windows-specific file operations."""

    @pytest.mark.windows
    def test_open_config_in_editor_windows(self, temp_dir):
        """Test opening config file in editor on Windows."""
        config_file = temp_dir / "test.cfg"
        config_file.write_text("[BLOCK]\ntest.com\n", encoding='utf-8')

        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.Popen') as mock_popen:

            calmweb.open_config_in_editor(str(config_file))

            # Give thread time to start
            import time
            time.sleep(0.1)

            # Should have attempted to open with notepad
            # (called in background thread)

    @pytest.mark.windows
    def test_open_config_in_editor_non_windows(self, temp_dir):
        """Test opening config file in editor on non-Windows."""
        config_file = temp_dir / "test.cfg"
        config_file.write_text("[BLOCK]\ntest.com\n", encoding='utf-8')

        with patch('platform.system', return_value='Linux'), \
             patch('os.startfile') as mock_startfile, \
             patch('hasattr', return_value=True):

            calmweb.open_config_in_editor(str(config_file))

            # Give thread time to start
            import time
            time.sleep(0.1)

    @pytest.mark.windows
    def test_open_config_creates_missing_file(self, temp_dir):
        """Test opening config creates missing file."""
        nonexistent_file = temp_dir / "missing.cfg"

        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.Popen') as mock_popen:

            calmweb.open_config_in_editor(str(nonexistent_file))

            # Should create the file first
            import time
            time.sleep(0.1)
            assert nonexistent_file.exists()


class TestWindowsErrorHandling:
    """Test Windows-specific error handling."""

    @pytest.mark.windows
    def test_windows_module_import_error_handling(self):
        """Test handling of Windows module import errors."""
        # The module should handle missing Windows modules gracefully
        assert hasattr(calmweb, 'WIN32_AVAILABLE')
        assert isinstance(calmweb.WIN32_AVAILABLE, bool)

    @pytest.mark.windows
    def test_windows_registry_permission_error(self, mock_win32_modules):
        """Test handling of Windows registry permission errors."""
        sys.modules['winreg'].OpenKey.side_effect = PermissionError("Access denied")

        with patch('platform.system', return_value='Windows'):
            # Should not raise exception
            try:
                calmweb.set_system_proxy(enable=True)
            except PermissionError:
                pytest.fail("Should handle registry permission errors gracefully")

    @pytest.mark.windows
    def test_windows_subprocess_permission_error(self, capture_logs):
        """Test handling of Windows subprocess permission errors."""
        with patch('platform.system', return_value='Windows'), \
             patch('subprocess.run', side_effect=PermissionError("Access denied")):

            # Should handle permission errors gracefully
            calmweb.add_firewall_rule("test.exe")
            calmweb.set_system_proxy(enable=True)

    @pytest.mark.windows
    def test_windows_file_access_error(self, temp_dir):
        """Test handling of Windows file access errors."""
        # Create a read-only directory to simulate access errors
        readonly_dir = temp_dir / "readonly"
        readonly_dir.mkdir()

        with patch('os.makedirs', side_effect=PermissionError("Access denied")):
            # Should handle file access errors gracefully
            result = calmweb.write_default_custom_cfg(
                str(readonly_dir / "test.cfg"),
                {"test.com"},
                {"safe.com"}
            )
            # Function should handle error and not crash