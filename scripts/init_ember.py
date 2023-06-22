#!/usr/bin/env python
import gc
import os
import json
import random

import ember
import argparse
import autogenmalware
import lightgbm as lgb


def main():
    prog = "train_ember"
    descr = "Train an ember model from a directory with raw feature files"
    parser = argparse.ArgumentParser(prog=prog, description=descr)
    parser.add_argument("-v", "--featureversion", type=int, default=2, help="EMBER feature version")
    parser.add_argument("-m", "--metadata", action="store_true", help="Create metadata CSVs")
    parser.add_argument("-t", "--train", action="store_true", help="Train an EMBER model")
    parser.add_argument("datadir", metavar="DATADIR", type=str, help="Directory with raw features")
    parser.add_argument("--optimize", help="gridsearch to find best parameters", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.datadir) or not os.path.isdir(args.datadir):
        parser.error("{} is not a directory with raw feature files".format(args.datadir))

    X_train_path = os.path.join(args.datadir, "X_train.dat")
    y_train_path = os.path.join(args.datadir, "y_train.dat")
    if not (os.path.exists(X_train_path) and os.path.exists(y_train_path)):
        print("Creating vectorized features")
        ember.create_vectorized_features(args.datadir, args.featureversion)
        
    if args.metadata:
        ember.create_metadata(args.datadir)

    if args.train:
        params = {
            "boosting": "gbdt",
            "objective": "binary",
            "num_iterations": 1000,
            "learning_rate": 0.05,
            "num_leaves": 2048,
            "max_depth": 15,
            "min_data_in_leaf": 50,
            "feature_fraction": 0.5
        }
        if args.optimize:
            params = ember.optimize_model(args.datadir)
            print("Best parameters: ")
            print(json.dumps(params, indent=2))

        print("Training LightGBM model")
        lgbm_model = ember.train_model(args.datadir, params, args.featureversion)
        lgbm_model.save_model(os.path.join(args.datadir, "model.txt"))



def trainTestSplit(variantList, numberTest):
    # variantList = '/home/infobeyond/workspace/variants/VirusShare_01db10a317194fe7c94a58fae14f787c_List'
    variantTrainList = str(variantList) + '_Train' #'/home/infobeyond/workspace/variants/VirusShare_01db10a317194fe7c94a58fae14f787c_Train_List'
    variantTestList = str(variantList) + '_Test' #'/home/infobeyond/workspace/variants/VirusShare_01db10a317194fe7c94a58fae14f787c_Test_List'
    # numberTest = 50

    fileNames = []
    fileNamesTrain = []
    fileNamesTest = []

    with open(variantList) as f:
        for filename in f:
            fileNames.append(filename)

    numberVariants = len(fileNames)
    numberTrain = numberVariants - numberTest

    #(len(fileNames) // 2)
    fileNamesTrain = random.sample(fileNames, k = numberTrain)

    for filename in fileNames:
        if filename not in fileNamesTrain:
            fileNamesTest.append(filename)


    if os.path.exists(variantTrainList):
        os.remove(variantTrainList)

    if os.path.exists(variantTestList):
        os.remove(variantTestList)

    with open(variantTrainList, "a") as wf:
        for filename in fileNamesTrain:
            wf.write(str(filename))

    with open(variantTestList, "a") as wf:
        for filename in fileNamesTest:
            wf.write(str(filename))

    return variantTrainList, variantTestList

def extractFeature(fileList, outputJsonlFile, label):
    ember.extract_raw_features(fileList, outputJsonlFile, label)

def list_malware_names(sourceDirectory='/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwares/',
                       outputFile='/media/infobeyond/New Volume/AutoGenMalware/Malware_Database/Malwares/peMalwaresList'):

    if os.path.exists(outputFile):
        os.remove(outputFile)

    files = os.listdir(sourceDirectory)
    with open(outputFile, "a") as wf:
        i = 0
        for f in files:
            i = i + 1
            print(f"Processing file {i}/{len(files)} ({(i / len(files)) * 100} %)")
            # wf.write(str(os.path.join(sourceDirectory, f.strip())) +', 1'+ "\n")
            wf.write(str(os.path.join(f.strip())) + "\n")
            pass

variant_directory_base = '/home/infobeyond/workspace/variants/AKMVG'
modelname = 'lightGBM'
def generateVariantTrainList(original_malware_name, variant_directory_base, modelname, numberPopulation, numberTest):
    variantDirectory = os.path.join(variant_directory_base, (modelname
                                                                                    + '_'
                                                                                    + str(numberPopulation)
                                                                                    + '_'
                                                                                    + str(original_malware_name)))

    variantListFile = os.path.join(variant_directory_base, (modelname
                                                                                    + '_'
                                                                                    + str(numberPopulation)
                                                                                    + '_'
                                                                                    + str(original_malware_name)
                                                                                    + '_List'))
    list_malware_names(variantDirectory, variantListFile)
    variantTrainList, variantTestList = trainTestSplit(variantListFile, numberTest)

    return variantDirectory, variantListFile, variantTrainList, variantTestList

if __name__ == "__main__":
    # main()
    # Extract raw features
    # raw_features_jsonl = '/home/infobeyond/workspace/variants/LightGBM_VirusShare_01db10a317194fe7c94a58fae14f787c/' \
    #                      'test_features.jsonl'
    # label = 1
    # fileList = '/home/infobeyond/workspace/variants/LightGBM_VirusShare_01db10a317194fe7c94a58fae14f787c_Test_List'
    # fileNames = []
    # with open(fileList) as f:
    #     for filename in f:
    #         fileNames.append(filename.strip())
    # extractFeature(fileNames, raw_features_jsonl, label)

    # newMalwareDirectory = '/home/infobeyond/workspace/variants/VirusShare_01db10a317194fe7c94a58fae14f787c/'

    # for i in range(1):
    #     print(i)
    # ember.create_metadata('/home/infobeyond/workspace/variants/')
    # ember.create_vectorized_features('/home/infobeyond/Downloads/ember_dataset_2018/ember_dataset_2018_2/ember2018')

    # import lightgbm as lgb
    #
    # lgbm_model = lgb.Booster(model_file="/home/infobeyond/Downloads/ember_dataset_2018/ember_dataset_2018_2/ember2018/ember_model_2018.txt")
    # # putty_data = open("~/putty.exe", "rb").read()
    #
    #
    # dir = '/home/infobeyond/workspace/variants/VirusShare_01db10a317194fe7c94a58fae14f787c'
    # # dir = '/home/infobeyond/workspace/VirusShare/peMalwares'
    # # dir = '/home/infobeyond/workspace/variants/test'
    # files = os.listdir(dir)
    #
    # for f in files:
    #     fbytes = open(os.path.join(dir, f), "rb").read()
    #     print(ember.predict_sample(lgbm_model, fbytes))
    #     # score, test = anal.get_malware_analysis(None, None, fbytes)
    #     # print(str(f) + '--' + str(score))


    # files = os.listdir(newMalwareDirectory)
    #
    # for f in files:
    #     fbytes = open(os.path.join(newMalwareDirectory, f), "rb").read()
    #
    #     res = extractor.raw_features(fbytes)
    #
    #     # rawFe = extractor.process_raw_features(res)
    #
    #     res['label'] = 1
    #
    #     json_object = json.loads(json.dumps(res))
    #
    #     json_formatted_str = json.dumps(json_object)
    #
    #     print(json_formatted_str)
    #
    #
    #     pass

    # trainTestSplit()

    print(gc.isenabled())

    malwareDirectory = '/home/infobeyond/workspace/VirusShare/AKMVG/malwares'
    malwareVariantDirectoryBase = '/home/infobeyond/workspace/variants/AKMVG'
    malwareListTextFile = '/home/infobeyond/workspace/VirusShare/peMalwareListAKMVG'
    variant_directory_base = '/home/infobeyond/workspace/variants/AKMVG'
    lightGbmTrainDirectory = '/home/infobeyond/Downloads/ember_dataset_2018/ember_dataset_2018_2/ember2018'
    modelname = 'lightGBM'
    fileStartNo = 1
    fileEndNo = 1
    numberPopulation = 300
    numberTest = 50
    trainSetAmountList = []
    trainSetIncremental = 20

    # training set amount
    pop = 160
    while True:
        if pop <= (numberPopulation - numberTest):
            trainSetAmountList.append(pop)
            pop = pop + trainSetIncremental
        else:
            break

    files = autogenmalware.filterMalwareFiles(malwareListTextFile, fileStartNo, fileEndNo)
    resultOutput = os.path.join(variant_directory_base, 'coverage_experiment_output')

    # if os.path.exists(resultOutput):
    #     os.remove(resultOutput)

    for originalMalwareFilename in files:
        try:
            # Split variants into train and test
            variantDirectory, variantListFile, variantTrainListFile, variantTestListFile =\
                generateVariantTrainList(originalMalwareFilename, variant_directory_base, modelname, numberPopulation,
                                         numberTest)
        except:
            continue

        raw_features_jsonl = os.path.join(lightGbmTrainDirectory, 'train_features_6.jsonl')
        label = 1
        for trainSetAmount in trainSetAmountList:

            if trainSetAmount == 0:
                lgbm_model = lgb.Booster(
                    model_file='/home/infobeyond/Downloads/ember_dataset_2018/ember_dataset_2018_2/ember2018/lightGBMCustom.txt')

            else:
                trainFileNames = []
                with open(variantTrainListFile) as f:
                    fileCounter = 1
                    for trainFileName in f:
                        if fileCounter <= trainSetAmount:
                            trainFileNames.append(os.path.join(variantDirectory, trainFileName.strip()))
                        else:
                            break
                        fileCounter = fileCounter + 1

                # extract raw features into "raw_features_jsonl" from binary files
                extractFeature(trainFileNames, raw_features_jsonl, label)

                # remove existing vectorized feature data
                if os.path.exists(os.path.join(lightGbmTrainDirectory, 'X_train.dat')):
                    os.remove(os.path.join(lightGbmTrainDirectory, 'X_train.dat'))

                if os.path.exists(os.path.join(lightGbmTrainDirectory, 'y_train.dat')):
                    os.remove(os.path.join(lightGbmTrainDirectory, 'y_train.dat'))

                if os.path.exists(os.path.join(lightGbmTrainDirectory, 'X_test.dat')):
                    os.remove(os.path.join(lightGbmTrainDirectory, 'X_test.dat'))

                if os.path.exists(os.path.join(lightGbmTrainDirectory, 'y_test.dat')):
                    os.remove(os.path.join(lightGbmTrainDirectory, 'y_test.dat'))

                # create vectorized features
                ember.create_vectorized_features(lightGbmTrainDirectory, noFiles=7)

                # train model
                savedModelFile = os.path.join(lightGbmTrainDirectory, 'lightGBMCustom_' + str(trainSetAmount) + '_'
                                              + str(originalMalwareFilename))

                if os.path.exists(savedModelFile):
                    os.remove(savedModelFile)

                lgbm_model = ember.train_model(lightGbmTrainDirectory)
                lgbm_model.save_model(savedModelFile)


            testMalwareVariantFiles = []
            with open(variantTestListFile) as f:
                for testFileName in f:
                    testMalwareVariantFiles.append(testFileName.strip())

            with open(resultOutput, "a") as wf:
                for testMalwareVariantFile in testMalwareVariantFiles:
                    try:
                        fbytes = open(os.path.join(variantDirectory, testMalwareVariantFile), "rb").read()
                        dr = ember.predict_sample(lgbm_model, fbytes)
                        del fbytes
                        gc.collect()
                        wf.write(str(originalMalwareFilename) + ";"
                                     + str(modelname) + ";"
                                     + 'AKMVG' + ";"
                                     + str(trainSetAmount) + ";"
                                     + str(testMalwareVariantFile) + ";"
                                     + str(dr) + " \n")
                    except:
                        wf.write(str(originalMalwareFilename) + ";"
                                     + str(modelname) + ";"
                                     + 'AKMVG' + ";"
                                     + str(trainSetAmount) + ";"
                                     + str(testMalwareVariantFile) + ";"
                                     + str('error') + " \n")

            del lgbm_model, wf, testMalwareVariantFiles, trainFileNames,f
            gc.collect()
        pass
    # ember.create_vectorized_features('/home/infobeyond/Downloads/ember_dataset_2018/ember_dataset_2018_2/ember2018/', noFiles=7)
    pass