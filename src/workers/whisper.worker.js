/* eslint-disable no-restricted-globals */

import { pipeline, env } from '@xenova/transformers';

// Skip local check to download from Hugging Face Hub
env.allowLocalModels = false;

// Singleton pattern for the pipeline
class MyTranscriptionPipeline {
    static task = 'automatic-speech-recognition';
    static model = 'Xenova/whisper-tiny.en';
    static instance = null;

    static async getInstance(progress_callback = null, modelName) {
        if (this.instance === null || this.model !== modelName) {
            this.model = modelName;
            // Force reload if model changes or first load
            this.instance = await pipeline(this.task, this.model, {
                quantized: true, // Utilize quantized models for smaller download & faster inference
                progress_callback
            });
        }
        return this.instance;
    }
}

self.addEventListener('message', async (event) => {
    const { type, audio, model } = event.data;

    if (type === 'TRANSCRIBE') {
        try {
            const transcriber = await MyTranscriptionPipeline.getInstance((data) => {
                // Pass progress back to main thread
                self.postMessage({
                    type: 'download', // Special internal type or mapped in Dashboard
                    data
                });
            }, model);

            // Run inference
            // Audio is expected to be a Float32Array
            const output = await transcriber(audio, {
                chunk_length_s: 30,
                stride_length_s: 5,
                language: 'english',
                task: 'transcribe',
                return_timestamps: true,
            });

            self.postMessage({
                type: 'RESULT',
                text: output.text,
                chunks: output.chunks // detailed timestamps if needed
            });

        } catch (error) {
            self.postMessage({
                type: 'ERROR',
                message: error.message
            });
        }
    }
});
