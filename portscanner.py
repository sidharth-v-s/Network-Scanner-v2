import dearpygui.dearpygui as dpg
import threading
from fontsetup import setUp
from themes import create_themes
from code import port_scanner
from resize import homeResize 

def resize():
    width, height = dpg.get_viewport_width(), dpg.get_viewport_height()
    dpg.set_item_width("main_window", width)
    dpg.set_item_height("main_window", height)
    
    dpg.set_item_pos("ip_text", [(width / 2) - 200, (height / 2) - 80])
    dpg.set_item_pos("input", [(width / 2) - 10, (height / 2) - 80])
    dpg.set_item_pos("scan_type_text", [(width / 2) - 200, (height / 2) - 40])
    dpg.set_item_pos("scan_type_combo", [(width / 2) - 10, (height / 2) - 40])
    dpg.set_item_pos("scan_button_ps", [(width / 2) - 10, (height / 2) + 0])
    dpg.set_item_pos("back_button_ps", [width - 120, 10])
    dpg.set_item_pos("result_text", [(width / 2) - 390, (height / 2) + 50])

def return_to_home():
    dpg.hide_item("main_window")
    dpg.show_item("main_window_home")
    homeResize()
    dpg.set_viewport_resize_callback(lambda: homeResize())

def run_scan():
    ip_address = dpg.get_value("input")
    scan_type = dpg.get_value("scan_type_combo")
    
    if not ip_address:
        dpg.set_value("result_text", "Please enter an IP address to scan.")
        return
        
    dpg.set_value("result_text", f"Starting {scan_type} scan...")
    
    # Run port scan in a separate thread to avoid freezing the UI
    def scan_thread():
        def update_callback(result):
            dpg.set_value("result_text", result)
        
        # Get the nmap arguments based on scan type
        scan_arguments = {
            "Basic Scan (-sS)": "-sS",
            "Version Detection (-sV)": "-sV",
            "OS Detection (-O)": "-O",
            "Comprehensive (-A)": "-A",
            "Fast Scan (-F)": "-F",
            "UDP Scan (-sU)": "-sU",
            "All Ports (-p-)": "-p-",
            "Top 100 Ports": "--top-ports 100"
        }
        
        nmap_args = scan_arguments.get(scan_type, "-A")  # Default to -A if not found
        port_scanner(ip_address, update_callback, nmap_args)
    
    threading.Thread(target=scan_thread, daemon=True).start()

def portscanner():
    create_themes()  # Create themes only once

    # Delete the existing window if it exists
    if dpg.does_item_exist("main_window"):
        dpg.delete_item("main_window")

    with dpg.window(tag="main_window", label="Port Scanner", pos=(0, 0), no_title_bar=True, no_resize=True, no_move=True):
        dpg.add_text("IP Scanner", tag="ps", color=(255, 255, 255, 255))
        dpg.add_separator(tag="separator")
        
        dpg.add_text("Enter The IP Address Here:", tag="ip_text", color=(255, 255, 255, 255))
        dpg.add_input_text(tag="input", height=30, width=200, hint="e.g. 192.168.1.100")
        
        dpg.add_text("Select Scan Type:", tag="scan_type_text", color=(255, 255, 255, 255))
        
        scan_types = [
            "Basic Scan (-sS)", 
            "Version Detection (-sV)", 
            "OS Detection (-O)", 
            "Comprehensive (-A)", 
            "Fast Scan (-F)", 
            "UDP Scan (-sU)", 
            "All Ports (-p-)",
            "Top 100 Ports"
        ]
        
        dpg.add_combo(
            items=scan_types, 
            default_value="Comprehensive (-A)", 
            tag="scan_type_combo", 
            width=200
        )
        
        dpg.add_button(label="Scan", tag="scan_button_ps", pos=(0, 0), width=100, height=30, callback=run_scan)
        dpg.add_button(label="Back", tag="back_button_ps", pos=(0, 0), width=100, height=30, callback=return_to_home)
        dpg.add_input_text(tag="result_text", multiline=True, readonly=True, default_value="", width=700, height=250)

        # Bind Themes
        dpg.bind_item_theme("scan_button_ps", "button_theme")
        dpg.bind_item_theme("input", "input_theme")
        dpg.bind_item_theme("scan_type_combo", "input_theme")
        dpg.bind_item_theme("back_button_ps", "button_theme")
        dpg.bind_item_theme("result_text", "input_theme_result")
        dpg.bind_item_font("ps", setUp())

    resize()
    dpg.set_viewport_resize_callback(lambda: resize())
    dpg.hide_item("main_window_home")

if __name__ == "__main__":
    dpg.create_context()
    dpg.create_viewport(title='IP Scanner', width=800, height=600)
    dpg.setup_dearpygui()

    # Import here to avoid circular imports
    from home import homeui
    homeui() 
    portscanner()

    # Set the global background color to match the theme
    dpg.set_viewport_clear_color((0, 0, 0, 255))

    dpg.show_viewport()
    dpg.start_dearpygui()

    dpg.destroy_context()