/* 
* Contract Execution Environment (CEE)
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/



#include <stdio.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <sys/time.h>

#include <thread>
#include <vector>

#include <limits.h>
#include <unistd.h>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"
// #include "isv_enclave_u.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
#include "network_ra.h"
// Needed to create enclave and do ecall.
#include "sgx_urts.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"
#include "service_provider.h"
#include "operations.h"



using namespace std;

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define N_TCS 1


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
// #define _T(x) x
int main(int argc, char* argv[])
{
    bool running = true;
    bool enclave_on = false;
    enclave_info_t enclave_info;
    double tic, toc;
    

    /* Communication config */
    int socket_init;
    bool sock_on = false;
    int sock_num[2]; // 0: DC, 1: iDA

    /* Init enclave*/
    enclave_on = enclave_init(&enclave_info); 

    while(running)
    {
        char inputChar;
        
        cout << "\n## CEE ## ready to roll:" << endl
        << "Press 1: Computation task 1. (Encrypt single data file)" << endl
        << "Press 2: Computation task 2. (Encrypt multiple data files)." << endl
        << "Press 3: Computation task 3. (Sum from 1 to 10000 for single file) inside enclave." << endl
        << "Press 4: Computation task 4. (Sum from 1 to 10000 for multiple files) inside enclave." << endl
        << "Press 5: Computation task 5. (Sum from 1 to 10000 for multiple files) outside enclave." << endl
        << "Press 6: Computation task 6. (training ANN model) inside enclave." << endl
        << "Press 7: Computation task 7. (training ANN model) outside enclave." << endl
        << "Press 8: Computation task 8. (training svm model) inside enclave." << endl
        << "Press 9: Computation task 9. (training svm model) outside enclave." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            // Exit
            case '0':
            {
                running = false;
                if (enclave_on) 
                {
                    enclave_close(&enclave_info);
                }
                break;
            }

            // Encrypt single data file
            case '1':
            {
                encrypt_file(1, 1);
                break;
            }

            // Encrypt multiple data files
            case '2':
            {
                int i, N, ret;
                double tTotal = 0;

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    encrypt_file(1, i+1);
                }

                tic = stime();
                ECALL_test_enclave(enclave_info.enclave_id, &status);
                toc = stime();
                tTotal += (toc - tic);

                printf("\nAverage time for [Encrypt multiple data files]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 1 [summation inside of the enclave for single file].
            case '3':
            {
                // Computing Task 1: a simple summation function
                enclave_compute_task1(&enclave_info, 1, 1); // DO 1's file 1 (will change later)
                break;
            }

            // Computing task 1 [summation inside of the enclave for multiple files].
            case '4':
            {
                int th, i, N, ret;
                double tTotal = 0;

                vector<std::thread> threads;

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    encrypt_file(1, i+1);
                }

                tic = stime();
                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    //Begin task 2 [training SVM classifier inside enclave].
                    threads.emplace_back(enclave_compute_task, &enclave_info, 1, 0, 1, N, 1);
                }

                for (thread & t : threads)
                {
                    t.join();
                }
                threads.clear();
                toc = stime();
                tTotal += (toc - tic);
                printf("\nAverage time for [summation inside of the enclave for multiple files]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 1 [summation outside of the enclave for multiple files].
            case '5':
            {
                int i, N, sum;
                double tTotal = 0;

                cout << "Number of files: ";
                cin  >> N;

                tic = stime();
                // Computing task 3 [training ANN classifier outside of the enclave].
                enclave_compute_task_normal(0, 1, N, 1);
                printf("\nAfter compute task.\n");
                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for [summation outside of the enclave for multiple files]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 2 [training SVM classifier inside of the enclave].
            case '6':
            {
                int th, i, N, ret;
                double tTotal = 0;

                vector<std::thread> threads;

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    encrypt_file(1, i+1);
                }

                tic = stime(); 

                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    //Begin task 2 [training SVM classifier inside enclave].
                    threads.emplace_back(enclave_compute_task, &enclave_info, 1, 0, 1, N, 2);
                }

                for (thread & t : threads) 
                {
                    t.join();
                }
                threads.clear();
                
                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for [training SVM classifier inside of the enclave]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 2 [training SVM classifier outside of the enclave].
            case '7':
            {
                int th, i, N;
                double tTotal = 0;

                vector<std::thread> threads;

                cout << "Number of files: ";
                cin  >> N;

                tic = stime(); 

                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    threads.emplace_back(enclave_compute_task_normal, 0, 1, N, 2);
                }

                for (thread & t : threads) 
                {
                    t.join();
                }
                threads.clear();

                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for [training SVM classifier outside of the enclave]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 3 [training ANN classifier inside of the enclave].
            case '8':
            {
                int th, i, N, ret;
                double tTotal = 0;

                vector<std::thread> threads;

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    // int encrypt_file(int DO_ID, int file_num)
                    encrypt_file(1, i+1);
                }

                tic = stime();

                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    threads.emplace_back(enclave_compute_task, &enclave_info, 1, 0, 1, N, 3);
                }

                for (thread & t : threads)
                {
                    t.join();
                }
                threads.clear();

                toc = stime();
                tTotal += (toc - tic);

                printf("\nAverage time for [training ANN classifier inside of the enclave]: %f seconds\n", tTotal);
                break;
            }

            // Computing task 3 [training ANN classifier outside of the enclave].
            case '9':
            {
                int i, N, sum;
                double tTotal = 0;

                cout << "Number of files: ";
                cin  >> N;

                tic = stime();
                // Computing task 3 [training ANN classifier outside of the enclave].
                enclave_compute_task_normal(0, 1, N, 3);
                printf("\nAfter compute task.\n");
                toc = stime();
                tTotal += (toc - tic);

                printf("\nAverage time for [training ANN classifier outside of the enclave]: %f seconds\n", tTotal);
                break;
            }
        }
    }
	
    return 0;
}