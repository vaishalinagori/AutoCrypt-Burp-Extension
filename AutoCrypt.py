from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from javax.swing import JMenuItem, JFileChooser
import subprocess
import os

# Global variables to store selected scripts
selected_encrypt_script = None
selected_decrypt_script = None

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("AutoCrypt")
        self.callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem("Encrypt", actionPerformed=lambda x: self.process_request(invocation, "encrypt")))
        menu.append(JMenuItem("Decrypt", actionPerformed=lambda x: self.process_request(invocation, "decrypt")))
        menu.append(JMenuItem("Select Encryption Script", actionPerformed=lambda x: self.select_script("encrypt")))
        menu.append(JMenuItem("Select Decryption Script", actionPerformed=lambda x: self.select_script("decrypt")))
        return menu

    def select_script(self, action_type):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(None)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            global selected_encrypt_script, selected_decrypt_script
            if action_type == "encrypt":
                selected_encrypt_script = file.getAbsolutePath()
                print("Selected encryption script:", selected_encrypt_script)
            elif action_type == "decrypt":
                selected_decrypt_script = file.getAbsolutePath()
                print("Selected decryption script:", selected_decrypt_script)

    def process_request(self, invocation, action_type):
        global selected_encrypt_script, selected_decrypt_script

        # Get the HTTP request
        request_info = invocation.getSelectedMessages()[0].getRequest()
        request = self.helpers.bytesToString(request_info)

        # Get the selected text
        selected_offset = invocation.getSelectionBounds()
        if selected_offset and selected_offset[0] != selected_offset[1]:
            selected_text = request[selected_offset[0]:selected_offset[1]]
        else:
            selected_text = self.extract_post_body(request)

        print("Input data for {}: {}".format(action_type, selected_text))

        # Determine which script to use
        if action_type == "encrypt" and selected_encrypt_script is not None:
            script_path = selected_encrypt_script
        elif action_type == "decrypt" and selected_decrypt_script is not None:
            script_path = selected_decrypt_script
        else:
            print("No script selected for {}".format(action_type))
            self.select_script(action_type)
            return

        # Run the selected script
        try:
            result = self.run_script(script_path, selected_text)
            if result:
                print("Script output: {}".format(result))
                # Replace the appropriate section of the request
                if selected_offset and selected_offset[0] != selected_offset[1]:
                    # Replace only the selected text
                    new_request = request[:selected_offset[0]] + result + request[selected_offset[1]:]
                else:
                    # Replace the entire POST body
                    new_request = self.replace_post_body(request, result)

                # Update the request with the new body
                invocation.getSelectedMessages()[0].setRequest(self.helpers.stringToBytes(new_request))
                print("Updated request sent.")
            else:
                print("No result from script.")
        except Exception as e:
            print("Error running script: {}".format(e))

    def extract_post_body(self, request):
        """ Extracts the POST body from the HTTP request """
        request_info = self.helpers.analyzeRequest(request)
        body_offset = request_info.getBodyOffset()
        return request[body_offset:]

    def replace_post_body(self, request, new_body):
        """ Replaces the POST body in the HTTP request with new_body """
        request_info = self.helpers.analyzeRequest(request)
        headers = request[:request_info.getBodyOffset()]
        return headers + new_body

    def run_script(self, script_path, input_data):
        """ Runs the specified script and passes input_data to it """
        temp_input_file = "temp_input.txt"
        try:
            # Write the input data to a temporary file
            with open(temp_input_file, 'w') as f:
                f.write(input_data)

            # Prepare the command based on the script type
            command = []
            if script_path.endswith(".py"):
                command = ["python3", script_path]
            elif script_path.endswith(".java"):
                # Compile the Java file first
                javac_command = ["javac", script_path]
                javac_process = subprocess.Popen(javac_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                javac_stdout, javac_stderr = javac_process.communicate()
                if javac_process.returncode != 0:
                    raise Exception("Java compilation error: {}".format(javac_stderr.decode()))
                
                # Extract the directory and class name for running the compiled Java class
                script_dir = os.path.dirname(script_path)
                class_name = os.path.basename(script_path).replace(".java", "")
                command = ["java", "-cp", script_dir, class_name]
            else:
                raise Exception("Unsupported script type")

            # Run the script
            with open(temp_input_file, 'r') as temp_input:
                process = subprocess.Popen(command, stdin=temp_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

            # Handle script output
            if process.returncode == 0:
                return stdout.decode()
            else:
                raise Exception("Script execution error: {}".format(stderr.decode()))
        except Exception as e:
            print("Error running script: {}".format(e))
            return None
        finally:
            # Clean up temporary files
            if os.path.exists(temp_input_file):
                os.remove(temp_input_file)
