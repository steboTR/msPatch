import requests
import json
import pandas as pd
from datetime import datetime, timedelta
import time
from pandas.io.json import json_normalize
import os
import argparse
import configparser
from sys import platform

pd.set_option('display.max_rows', 500)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)

# print(os.path.dirname(os.path.realpath(__file__)))

def read_conf():
    config = configparser.ConfigParser(allow_no_value=True)
    config.read('./msPatch.conf')

    cfg = {}

    #global options
    cfg['msAPIkey'] = config.get('global','msAPIkey')
    cfg['msAPIurl'] = config.get('global','msAPIurl')
    cfg['email'] = config.get('global','recipientEmail')

    return cfg

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interactive', action='store_true', help='Starts msPatch in interactive mode.')

args = parser.parse_args()
INTERACTIVE = args.interactive

if INTERACTIVE:
    patchId = input("YYYY-MMM of patches or leave blank for current month ("+datetime.now().strftime('%Y')+"-"+datetime.now().strftime('%h')+")? ")
    outputPath = input("Output Path: Leave blank for current dir. ("+os.path.dirname(os.path.realpath(__file__))+"/output)")
    if patchId == '':
        patchId = datetime.now().strftime('%Y')+"-"+datetime.now().strftime('%h')
    if outputPath == '':
        outputPath = os.path.dirname(os.path.realpath(__file__))+"/output"
    print(str(datetime.now())+' :: Looking up '+patchId)
else:
    patchId = datetime.now().strftime('%Y')+"-"+datetime.now().strftime('%h')
    outputPath = os.path.dirname(os.path.realpath(__file__))+"/output"

cfg = read_conf()

url = cfg['msAPIurl']+patchId

querystring = {"api-version":"latest"}

payload = ""
headers = {
    'Accept': "application/json",
    'api-key': cfg['msAPIkey'],
    'User-Agent': "steboAPI",
    'Host': "api.msrc.microsoft.com",
    'accept-encoding': "gzip, deflate",
    }

response = requests.request("GET", url, data=payload, headers=headers, params=querystring)

startTime = time.time()

while "200" not in str(response):
    elapsedtime = time.time() - startTime

    if elapsedtime > 3600:
        #send report on linux
        if platform == "linux":
            os.system("echo '' | mutt -s 'MSPatch :: SCRIPT RUNNING; NO RESULTS'"+cfg['email'])
        print("Email sent, still no results")

    print(str(datetime.now())+' :: No Report Found. Waiting 5 min.', end='\r')
    time.sleep(300)
    response = requests.request("GET", url, data=payload, headers=headers, params=querystring)

print(str(datetime.now())+' :: Report Found')

jsonObject = json.loads(response.text)
masterTable = json_normalize(jsonObject)

print(str(datetime.now())+' :: Generating Vuln Table')
#generate Vuln Table
vulnTable = pd.DataFrame(masterTable['Vulnerability'][0])
threatOutput = pd.DataFrame([])
for index, row in vulnTable.iterrows():
    genThreat = pd.DataFrame([])
    impactTable = pd.DataFrame([])
    rowThreatTable = pd.DataFrame(row['Threats'])
    type1 = rowThreatTable.loc[(rowThreatTable['Type'] == 1)].reset_index().drop(columns="index")
    type0 = rowThreatTable.loc[(rowThreatTable['Type'] == 0)].reset_index().drop(columns="index")
    if type1.shape[0] == 1:

        threat = type1
        impact = threat['Description'][0].get('Value').split(";")
        impactList = []
        for item in impact:
            impactList.append(item.split(":"))
        impactTable = pd.DataFrame(impactList).T
        impactTable.columns = impactTable.iloc[0]
        impactTable = impactTable[1:]
    else:
        for index, threat in type1.iterrows():
            print(threat)
            impact = threat['Description'][0].get('Value').split(";")
            impactList = []
            for item in impact:
                impactList.append(item.split(":"))
            impactTable = pd.DataFrame(impactList).T
            impactTable.columns = impactTable.iloc[0]
            impactTable = impactTable[1:]
    impactTable = impactTable.reset_index().drop(columns='index')

    if type0.shape[0] == 1:
        try:
            impactTable['genThreat'] = type0['Description'][0]
        except:
            impactTable['genThreat'] = ""
    else:
        for index, generalThreat in type0.iterrows():
            genThreat = genThreat.append(generalThreat['Description'], ignore_index=True)
            try:
                impactTable['genThreat'] = ", ".join(genThreat['Value'].drop_duplicates().tolist())
            except:
                impactTable['genThreat'] = ""

    impactTable['vulnTitle'] = row['Title'].get('Value')
    impactTable['DiscoveryDateSpecified'] = row['DiscoveryDateSpecified']
    impactTable['ReleaseDateSpecified'] = row['ReleaseDateSpecified']
    impactTable['vulnCVE'] = row['CVE']
    impactTable['impactedProductList'] = str(row['ProductStatuses'][0].get('ProductID')).replace("[","").replace("]","").replace("'","")
    if row['CVSSScoreSets'] != []:
        scoreList = []
        for score in row['CVSSScoreSets']:
            scoreList.append(score['BaseScore'])
        impactTable['CVSSBase'] = max(scoreList)
    else:
        impactTable['CVSSBase'] = 'noScoreProvided'
    for notes in row['Notes']:
        if notes['Title'] == 'Description':
            impactTable['Summary'] = notes['Value'].replace('<p>','').replace('</p>','').replace("\n",'')
    threatOutput = threatOutput.append(impactTable, sort=False)

print(str(datetime.now())+' :: Done')
print(str(datetime.now())+' :: Generating Product Tree')
#generate ProductTreeBranchTable
ProductTreeBranchTable = pd.DataFrame(masterTable['ProductTree.Branch'][0])
ProductTreeBranchTable = json_normalize(ProductTreeBranchTable["Items"][0])
ProductTreeBranchOutput = pd.DataFrame([])
for index, row in ProductTreeBranchTable.iterrows():
    temp = pd.DataFrame([])
    for item in row['Items']:
        ProductID = item['ProductID']
        SpecificProduct = item['Value']
        temp = temp.append(pd.DataFrame({'ProductID': item['ProductID'],'SpecificProduct': item['Value']}, index=[0]), ignore_index=True,sort=True)
    temp['name'] = row['Name']
    temp['Type'] = row['Type']
    ProductTreeBranchOutput = ProductTreeBranchOutput.append(temp)

#generate ProductTree.FullProductName
productFullTable = pd.DataFrame(masterTable['ProductTree.FullProductName'][0])
print(str(datetime.now())+' :: Done')

print(str(datetime.now())+' :: Summarizing')
threatOutput = threatOutput.reset_index()
for index, row in threatOutput.iterrows():
    temp = pd.DataFrame([])
    temp = pd.DataFrame(row['impactedProductList'].replace(" ","").split(","))
    temp = temp.merge(ProductTreeBranchOutput, left_on=0, right_on='ProductID').drop(columns=0)
    tempProduct = pd.DataFrame([])
    threatOutput.at[index, 'impactedProducts'] = ", ".join(temp.SpecificProduct.tolist())

# summary = threatOutput.loc[((threatOutput['Latest Software Release'] == 'Exploitation More Likely') | (threatOutput['Older Software Release'] == 'Exploitation More Likely')) & ((threatOutput['genThreat'].str.contains('Elevation of Privilege')) | (threatOutput['genThreat'] =='Remote Code Execution')) | (threatOutput['Exploited'] == 'Yes')]
summary = threatOutput.loc[(((threatOutput['Latest Software Release'] == 'Exploitation More Likely') | (threatOutput['Older Software Release'] == 'Exploitation More Likely')) & (threatOutput['genThreat'] =='Remote Code Execution')) | (threatOutput['Exploited'] == 'Yes')].drop(columns='index')
summary = summary.drop(columns="impactedProductList")
summary = summary[['vulnTitle','vulnCVE','genThreat','Exploited','CVSSBase','Summary','impactedProducts']]
print(str(datetime.now())+' :: Done')
print(str(datetime.now())+' :: Writing to Excel')

startPosition = 1
writer = pd.ExcelWriter(outputPath+"/msPatch_"+patchId.replace("-","_")+".xlsx", engine='xlsxwriter')
workbook=writer.book
# worksheet = workbook.add_worksheet('Summary')
cellFormatTitle = workbook.add_format({'font_name': 'Calibri', 'font_size': 16, 'bold':True, 'font_color': 'black', 'align': 'left'})
cellFormatBold = workbook.add_format({'font_name': 'Calibri', 'font_size': 12, 'bold':True, 'font_color': 'black'})
cellFormatBold.set_border(2)
cellFormatNormal = workbook.add_format({'font_name': 'Calibri', 'font_size': 12, 'bold':False, 'font_color': 'black','text_wrap': True})
cellFormatNormal.set_border(2)
formatEmpty = workbook.add_format({'bg_color': 'silver'})
# cellFormatBlack.set_bg_color('black')


for index, row in summary.iterrows():
    title = row['vulnCVE']+" | "+row['vulnTitle']
    lastUp = "Last updated: "+datetime.today().strftime("%d %b %Y")
    refUrl = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/"+row['vulnCVE']
    columnsText = [
        "Threat Type",
        "External Context",
        "Historical Similarity (ITW)",
        "Offensive Attractiveness",
        "Known Attacks",
        "Exploit Forecast",
        "References"]
    tempFormatter = pd.DataFrame({"Forecast Factor":columnsText,"Supporting Information":"","Summary":""})
    tempFormatter.at[0, 'Supporting Information'] = row['genThreat']
    # tempFormatter.at[0, 'Summary'] = row['Summary']
    tempFormatter.at[6, 'Supporting Information'] = refUrl

    tempFormatter.to_excel(writer,'Summary',startrow=startPosition+1, startcol=0, index=False)

    worksheet = writer.sheets['Summary']
    # worksheet.write('A'+str(startPosition+3),tempFormatter, cellFormatBlack)
    worksheet.merge_range('A'+str(startPosition)+':B'+str(startPosition), title, cellFormatTitle)
    worksheet.merge_range('A'+str(startPosition+1)+':B'+str(startPosition+1), lastUp, cellFormatTitle)
    worksheet.merge_range('C'+str(startPosition+3)+':C'+str(startPosition+9), row['Summary'], cellFormatNormal)
    worksheet.set_column('A:A', 22.2, cellFormatBold)
    worksheet.set_column('B:B', 67, cellFormatNormal)
    worksheet.set_column('C:C',160)
    startPosition = startPosition+11
# summary.to_excel(writer,'summary', index=False)
threatOutput.to_excel(writer,"threat", index=False)
vulnTable.to_excel(writer, "raw", index=False)
productFullTable.to_excel(writer,"productFullTable", index=False)
ProductTreeBranchOutput.to_excel(writer,"productTreeBranch", index=False)

# worksheet.conditional_format('A1:C'+str(startPosition), {'type':'blanks', 'format': formatEmpty})
writer.close()


if INTERACTIVE:
    import subprocess

    if platform =='darwin':
        applescript = """
        display dialog "MS PATCH DONE" ¬
        with title "This is a pop-up window" ¬
        with icon caution ¬
        buttons {"OK"}
        """

        subprocess.call("osascript -e '{}'".format(applescript), shell=True)

        print(str(datetime.now())+' :: Done')
    else:
        print("Done")

#send report on linux
if platform == "linux":
    os.system("echo '' | mutt -s 'MSPatch :: PATCH TUESDAY REPORT DONE' "+cfg['email']+" -a "+outputPath+"/msPatch_"+patchId.replace("-","_")+".xlsx")
