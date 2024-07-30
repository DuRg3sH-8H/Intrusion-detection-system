import unittest
from unittest.mock import MagicMock
from app import TrafficAnalyzerApp
import tkinter as tk

class TestTrafficAnalyzerApp(unittest.TestCase):
    
    def setUp(self):
        self.root = MagicMock()
        self.app = TrafficAnalyzerApp(self.root)
    
    def test_handle_packet(self):
        # Mock a packet with necessary attributes
        packet = MagicMock()
        packet.__getitem__.side_effect = lambda key: {'src': '192.168.0.1', 'dst': '192.168.0.2', 'sport': 1234, 'dport': 80, 'proto': 6}.get(key)
        
        # Mock the predict_traffic method
        self.app.predict_traffic = MagicMock(return_value=0)  # Mock prediction
        
        # Call the handle_packet method
        self.app.handle_packet(packet)
        
        # Assert that the tree insert method was called with the expected values
        self.app.tree.insert.assert_called_once_with("", "end", text="1", values=(1, '192.168.0.1', 1234, '192.168.0.2', 80, 'TCP', 'Normal'))
    
    def test_get_traffic_type(self):
        # Test with a normal prediction
        predicted_class = 0
        traffic_type = self.app.get_traffic_type(predicted_class)
        self.assertEqual(traffic_type, 'Normal')
        
        # Test with a predicted attack
        predicted_class = 1
        traffic_type = self.app.get_traffic_type(predicted_class)
        self.assertEqual(traffic_type, 'dos')
        
    def test_start_capture(self):
        # Ensure capture thread is started and buttons are updated accordingly
        self.app.capture_thread = MagicMock()
        self.app.start_button.config = MagicMock()
        self.app.stop_button.config = MagicMock()
        
        self.app.start_capture()
        
        self.assertTrue(self.app.capture_thread.start.called)
        self.app.start_button.config.assert_called_once_with(state=tk.DISABLED)
        self.app.stop_button.config.assert_called_once_with(state=tk.NORMAL)
        
    def test_stop_capture(self):
        # Ensure capture thread is stopped and buttons are updated accordingly
        self.app.capture_thread = MagicMock()
        self.app.start_button.config = MagicMock()
        self.app.stop_button.config = MagicMock()
        
        self.app.stop_capture()
        
        self.assertFalse(self.app.capture_running)
        self.app.start_button.config.assert_called_once_with(state=tk.NORMAL)
        self.app.stop_button.config.assert_called_once_with(state=tk.DISABLED)
        
    # Add more test cases as needed

if __name__ == '__main__':
    unittest.main()
