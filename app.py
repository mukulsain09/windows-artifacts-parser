from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import threading
import uuid
import datetime
import logging
import tempfile
import shutil

# Set up logging for the Flask app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import core_logic functions
try:
    import core_logic
except ImportError as e:
    logger.error(f"Failed to import core_logic: {e}. Ensure core_logic.py is in the same directory.")
    # Exit or handle gracefully if core_logic is essential
    exit(1)

app = Flask(__name__, static_folder='web', template_folder='web', static_url_path='')

# In-memory store for background tasks
# { 'task_id': {'status': 'pending/in_progress/completed/failed', 'message': '', 'result': 'path/data', 'progress': 0} }
tasks = {}

def run_in_background(task_id, func, *args, **kwargs):
    """Helper to run a function in a background thread and update task status."""
    tasks[task_id] = {'status': 'in_progress', 'message': 'Task started...', 'progress': 0}
    try:
        result = func(*args, **kwargs)
        tasks[task_id]['status'] = 'completed'
        tasks[task_id]['message'] = result.get('message', 'Task completed.')
        tasks[task_id]['result'] = result
    except Exception as e:
        logger.exception(f"Background task {task_id} failed:")
        tasks[task_id]['status'] = 'failed'
        tasks[task_id]['message'] = str(e)
        tasks[task_id]['error'] = str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/parse_folder', methods=['POST'])
def api_parse_folder():
    data = request.get_json()
    folder_path = data.get('folder_path')
    
    if not folder_path:
        return jsonify({"status": "error", "message": "No folder_path provided"}), 400
    if not os.path.isdir(folder_path):
        return jsonify({"status": "error", "message": f"Invalid folder path: {folder_path}"}), 400

    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_folder_core, folder_path)).start()
    
    return jsonify({"status": "success", "message": "Parsing initiated in background", "task_id": task_id}), 202

@app.route('/api/parse_shellbags', methods=['POST'])
def api_parse_shellbags():
    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_shellbags_core)).start()
    return jsonify({"status": "success", "message": "ShellBags parsing initiated in background", "task_id": task_id}), 202

@app.route('/api/artifacts', methods=['GET'])
def api_get_artifacts():
    try:
        artifacts = core_logic.get_all_artifacts_json()
        return jsonify(artifacts), 200
    except Exception as e:
        logger.exception("Error fetching artifacts:")
        return jsonify({"status": "error", "message": f"Failed to fetch artifacts: {str(e)}"}), 500

@app.route('/api/clear_db', methods=['POST'])
def api_clear_db():
    try:
        result = core_logic.clear_database_core()
        return jsonify(result), 200
    except Exception as e:
        logger.exception("Error clearing database:")
        return jsonify({"status": "error", "message": f"Failed to clear database: {str(e)}"}), 500

@app.route('/api/export_csv', methods=['GET'])
def api_export_csv():
    temp_dir = None
    response = None # Initialize response outside try block
    try:
        # Generate a unique filename for the export
        filename = f"artifacts_export_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
        # Temporarily save the file
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)
        
        result = core_logic.generate_csv_report(filepath)
        if result['status'] == 'success':
            # send_file will handle closing the file
            response = send_file(filepath, as_attachment=True, download_name=filename)
            # Schedule cleanup after the response is sent
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.error(f"Error cleaning up temp directory {temp_dir}: {e}")
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        logger.exception("Error exporting CSV:")
        return jsonify({"status": "error", "message": f"Failed to export CSV: {str(e)}"}), 500
    finally:
        # If an error occurred before send_file was called, temp_dir might exist
        # Also, check if response was created and cleanup was not scheduled, for cases where an error happened after creating temp_dir but before send_file or @response.call_on_close
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, 'call_on_close')):
             try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir} due to an error or incomplete response setup.")
             except Exception as e:
                logger.error(f"Error during error cleanup of temp directory {temp_dir}: {e}")


@app.route('/api/export_pdf', methods=['POST'])
def api_export_pdf():
    report_details = request.get_json()
    temp_dir = None
    response = None # Initialize response outside try block
    try:
        filename = f"artifacts_report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)
        
        result = core_logic.generate_pdf_report_core(filepath, report_details)
        if result['status'] == 'success':
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.error(f"Error cleaning up temp directory {temp_dir}: {e}")
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        logger.exception("Error exporting PDF report:")
        return jsonify({"status": "error", "message": f"Failed to export PDF report: {str(e)}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, 'call_on_close')):
             try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir} due to an error or incomplete response setup.")
             except Exception as e:
                logger.error(f"Error during error cleanup of temp directory {temp_dir}: {e}")


@app.route('/api/correlations', methods=['GET'])
def api_get_correlations():
    try:
        correlations = core_logic.get_correlations_json()
        return jsonify(correlations), 200
    except Exception as e:
        logger.exception("Error fetching correlations:")
        return jsonify({"status": "error", "message": f"Failed to fetch correlations: {str(e)}"}), 500

@app.route('/api/export_correlation_pdf', methods=['POST'])
def api_export_correlation_pdf():
    report_details = request.get_json()
    temp_dir = None
    response = None # Initialize response outside try block
    try:
        filename = f"correlation_report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)
        
        result = core_logic.generate_correlation_pdf_core(filepath, report_details)
        if result['status'] == 'success':
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.error(f"Error cleaning up temp directory {temp_dir}: {e}")
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        logger.exception("Error exporting correlation PDF:")
        return jsonify({"status": "error", "message": f"Failed to export correlation PDF: {str(e)}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, 'call_on_close')):
             try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir} due to an error or incomplete response setup.")
             except Exception as e:
                logger.error(f"Error during error cleanup of temp directory {temp_dir}: {e}")

@app.route('/api/task_status/<task_id>', methods=['GET'])
def api_task_status(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'status': 'error', 'message': 'Task not found'}), 404
    return jsonify(task)


@app.route('/correlation')
def correlation():
    return render_template('correlation.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)